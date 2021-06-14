const BN = require('bn.js');
const utils = require('./utils/utils.js');
const bn128 = require('./utils/bn128.js');
const elgamal = require('./utils/elgamal.js');
const aes = require('./utils/aes.js');
const Service = require('./utils/service.js'); 
const ABICoder = require('web3-eth-abi');
const BigNumber = require('bignumber.js');
const { soliditySha3 } = require('web3-utils');

var sleep = (wait) => new Promise((resolve) => {
    setTimeout(resolve, wait);
});


class ClientBase {
    /**
    Constrct a client, with given web3 object, Beldex contract, and home account (Ethereum address). 

    @param web3 A web3 object.
    @param beldex The Beldex contract address.
    @param home The home account (Ethereum address).
    */
    constructor(web3, beldex, home) {
        if (web3 === undefined)
            throw "1st arg should be an initialized Web3 object.";
        if (beldex === undefined)
            throw "2nd arg should be a deployed Beldex contract object.";
        if (home === undefined)
            throw "3rd arg should be the address of an Ethereum account.";

        // console.log("Beldex contract: " + beldex.options.address);
        // console.log("Native account: " + home);

        this.web3 = web3;
        this.beldex = beldex;
        this.home = home;
    }

    /**
    Need a separate initialization method by design because we want the async/await feature which can not be used for a constructor.
    */
    async init() {

        // 'this' is special in Javascript compared to other languages, it does NOT refer to the Client object when inside some context. 
        // So better use an alias to fix our reference to the Client object.
        // Reference: https://stackoverflow.com/questions/20279484/how-to-access-the-correct-this-inside-a-callback
        var that = this;

        that.service = new Service();

        that.gasLimit = 5470000;

        // TODO: set transaction confirmation blocks for testing?
        // Reference: https://github.com/ethereum/web3.js/issues/2666
        // This option is only available in web3 1.3.0, but not in 1.2.1
        // web3.transactionConfirmationBlocks = 1;

        that.round_base = await that.beldex.methods.round_base().call();
        that.round_len = await that.beldex.methods.round_len().call();

        // 3100 is the estimated milliseconds of mining a block. Determined empirically. IBFT, block time.
        that.blockMinedTime = 3100;
        if (that.round_base == 0)
            that.roundUnitTime = that.blockMinedTime; 
        else if (that.round_base == 1)
            that.roundUnitTime = 1000; // 1 second
        else
            throw new Error("Invalid round base.");

        // The amount of tokens represented by one unit.
        // Most of the time, one token is too small and it is not worthwhile to use private 
        // transaction for such small amount. Hence in Beldex, we contrain all private operations 
        // to take place in terms of unit that can represent a large amount of tokens. For example,
        // a reasonable choice of 1 unit could be 1e16 wei (0.01 ETH).
        that.unit = await that.beldex.methods.unit().call();

        this._transfers = new Set();

        /**
        Register the TransferOccurred event for this client.
        Since a transfer is triggered by a sender, it is necessary to register this event to notify a transfer "receiver" to keep track of local account state (without manually synchronizing with contract).
        */
        this.beldex.events.TransferOccurred({})
            .on('data', (event) => {
                console.log("Receive TransferOccurred event");
                if (that._transfers.has(event.transactionHash)) {
                    // This is the sender of the transfer operation, hence we will simply return.
                    that._transfers.delete(event.transactionHash);
                    return;
                }
                var account = that.account;
                event.returnValues['parties'].forEach((party, i) => {
                    if (bn128.pointEqual(account.publicKey(), party)) {
                        var blockNumber = event.blockNumber;
                        web3.eth.getBlock(blockNumber).then(async (block) => {
                            if (that.round_base == 0)
                                account._state = await account.update(block.number);
                            else if (that.round_base == 1)
                                account._state = await account.update(block.timestamp);
                            else
                                throw new Error("Invalid round base.");

                            web3.eth.getTransaction(event.transactionHash).then((transaction) => {
                                var inputs;
                                that.beldex._jsonInterface.forEach((element) => {
                                    if (element['name'] == "transfer")
                                        inputs = element['inputs'];
                                });
                                // slice(10) because the first 10 bytes are used for the Method ID (function selector): 0x********
                                // NOTE: in binary mode, this is just 4 bytes, but since the transaction stores the input as readable
                                // ascii string, hence '0x' and 8 base-16 chars (representing 4 bytse) will constitute 10 bytes.
                                // ABI encoding: https://solidity.readthedocs.io/en/latest/abi-spec.html#argument-encoding
                                var parameters = web3.eth.abi.decodeParameters(inputs, "0x" + transaction.input.slice(10));
                                var ct = elgamal.unserialize([parameters['C'][i], parameters['D']]);
                                var value = elgamal.decrypt(ct, account.privateKey());
                                if (value > 0) {
                                    account._state.pending += value;
                                    console.log("Transfer of " + value + " received! Balance now " + account.balance() + ".");
                                }
                            });
                        });
                    }
                });
            })
            .on('error', (error) => {
                console.log(error); 
            });


        /**
        Beldex account, containing various information such as the public/private key pair, balance, etc.
        */
        this.account = new function() {
            this.keypair = undefined;
            this.aesKey = undefined;
            this._state = {
                available: 0,
                pending: 0,
                nonceUsed: 0,
                lastRollOver: 0
            };

            this.update = async (counter) => {
                var updated = {};
                updated.available = this._state.available;
                updated.pending = this._state.pending;
                updated.nonceUsed = this._state.nonceUsed;
                updated.lastRollOver = await that._getRound(counter);
                if (this._state.lastRollOver < updated.lastRollOver) {
                    updated.available += updated.pending;
                    updated.pending = 0;
                    updated.nonceUsed = false;
                }
                return updated;
            };

            this.available = () => {
                return this._state.available;
            };

            this.setAvailable = (value) => {
                this._state.available = value;
            };

            this.pending = () => {
                return this._state.pending;
            };

            this.setPending = (value) => {
                this._state.pending = value;
            };

            this.lastRollOver = () => {
                return this._state.lastRollOver;
            };

            this.balance = () => {
                return this._state.available + this._state.pending;
            };

            this.publicKey = () => {
                return this.keypair['y'];
            };

            this.privateKey = () => {
                return this.keypair['x'];
            };

            this.publicKeySerialized = () => {
                return bn128.serialize(this.keypair['y']);
            };

            this.privateKeySerialized = () => {
                return bn128.bytes(this.keypair['x']);
            };

            this.publicKeyEncoded = () => {
                return bn128.serializedToEncoded(this.publicKeySerialized());
            };

            this.publicKeyHash = () => {
                var encoded = ABICoder.encodeParameter("bytes32[2]", this.publicKeySerialized());
                return soliditySha3(encoded); 
            };

        };
        // First update to initialize the state.
        this.account._state = await this.account.update();

    }

}

module.exports = ClientBase;