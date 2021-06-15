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

    static async registered (beldex, pubKey) {
        var encoded = ABICoder.encodeParameter("bytes32[2]", pubKey);
        var hashedKey = soliditySha3(encoded);
        return await beldex.methods.registered(hashedKey).call();
    }

    async setRedeemFeeStrategy (numerator, denominator) {
        var that = this;
        let transaction = that.beldex.methods.setRedeemFeeStrategy(numerator, denominator)
                .send({from: that.home, gas: that.gasLimit})
                .on('transactionHash', (hash) => {
                    console.log("Change redeem fee submitted (txHash = \"" + hash + "\").");
                })
                .on('receipt', (receipt) => {
                    console.log("Change redeem fee successful.");
                })
                .on('error', (error) => {
                    console.log("Change redeem fee failed: " + error);
                    throw error;
                });
        return transaction;
    }

    async setTransferFeeStrategy (numerator, denominator) {
        var that = this;
        let transaction = that.beldex.methods.setTransferFeeStrategy(numerator, denominator)
                .send({from: that.home, gas: that.gasLimit})
                .on('transactionHash', (hash) => {
                    console.log("Change transfer fee submitted (txHash = \"" + hash + "\").");
                })
                .on('receipt', (receipt) => {
                    console.log("Change transfer fee successful.");
                })
                .on('error', (error) => {
                    console.log("Change transfer fee failed: " + error);
                    throw error;
                });
        return transaction;
    }

    async setRoundBase (round_base) {
        var that = this;
        let transaction = that.beldex.methods.setRoundBase(round_base)
                .send({from: that.home, gas: that.gasLimit})
                .on('transactionHash', (hash) => {
                    console.log("Set round base submitted (txHash = \"" + hash + "\").");
                })
                .on('receipt', (receipt) => {
                    console.log("Set round base successful.");
                    that.round_base = round_base;
                })
                .on('error', (error) => {
                    console.log("Set epohc base failed: " + error);
                    throw error;
                });
        return transaction;
    }

    async setRoundLen (round_len) {
        var that = this;
        let transaction = that.beldex.methods.setRoundLen(round_len)
                .send({from: that.home, gas: that.gasLimit})
                .on('transactionHash', (hash) => {
                    console.log("Set round length submitted (txHash = \"" + hash + "\").");
                })
                .on('receipt', (receipt) => {
                    console.log("Set round length successful.");
                    that.round_len = round_len;
                })
                .on('error', (error) => {
                    console.log("Set epohc length failed: " + error);
                    throw error;
                });
        return transaction;
    }

    async setBeldexAgency (beldexAgency) {
        var that = this;
        let transaction = that.beldex.methods.setBeldexAgency(beldexAgency)
                .send({from: that.home, gas: that.gasLimit})
                .on('transactionHash', (hash) => {
                    console.log("Set beldex agency submitted (txHash = \"" + hash + "\").");
                })
                .on('receipt', (receipt) => {
                    console.log("Set beldex agency successful.");
                })
                .on('error', (error) => {
                    console.log("Set beldex agency failed: " + error);
                    throw error;
                });
        return transaction;
    }


    /**
    Get the round corresponding to the given timestamp (if not given, use current time).
    This round is based on time, and does not start from 0, because it simply divides the timestamp by round length.

    TODO: should change to block based.

    @param timestamp The given timestamp. Use current time if it is not given.

    @return The round corresponding to the timestamp (current time if not given).
    */
    async _getRound (counter) {
        var that = this;
        if (that.round_base == 0) {
            if (counter === undefined)
                return Math.floor((await that.web3.eth.getBlockNumber()) / that.round_len);
            else
                return counter / that.round_len; 
        }
        else if (that.round_base == 1)
            return Math.floor((counter === undefined ? (new Date).getTime() / 1000 : counter) / that.round_len);
        else
            throw new Error("Invalid round base.");
    }

    /**
    Get seconds away from next round change.

    TODO: should change to block based.
    */
    async _away () {
        var that = this;
        if (that.round_base == 0) {
            var current = await that.web3.eth.getBlockNumber();
            return Math.ceil(current / that.round_len) * that.round_len - current;
        }
        else if (that.round_base == 1) {
            var current = (new Date).getTime();
            return (Math.ceil(current / (that.round_len * 1000)) * (that.round_len * 1000) - current) / 1000;
        }
    }

    checkRegistered () {
        var that = this;
        if (that.account.keypair === undefined)
            throw "Call register() first to register an account.";
    }

    checkValue (value) {
        if (value <= 0 || value > elgamal.MAX_PLAIN)
            throw "Invalid value: " + value;
    }

    async getGuess () {
        var that = this;
        that.checkRegistered();
        let encGuess = await that.beldex.methods.getGuess(that.account.publicKeySerialized()).call();
        if (encGuess == null)
            return 0;
        var guess = aes.decrypt(encGuess.slice(2), that.account.aesKey);
        guess = parseInt(guess, 16);
        console.log("guess: ", guess);
        return guess;
    }

    /**
    Read account balance from Beldex contract.
    
    @return A promise that is resolved with the balance.
    */
    async readBalanceFromContract () {
        var that = this;
        that.checkRegistered();
        let currentRound = await that._getRound();
        let encBalances = await that.beldex.methods.getBalance([that.account.publicKeySerialized()], currentRound + 1).call();
        var encBalance = elgamal.unserialize(encBalances[0]);

        var guess = await that.getGuess();

        var balance = elgamal.decrypt(encBalance, that.account.privateKey(), guess);
        console.log("Read balance successfully: " + balance);
        return balance;
    }

    /**
    Synchronize the local account state with that in the Beldex contract.
    Use this when we lose track of the local account state.
    
    @return A promise.
    */
    async syncAccountState () {
        var that = this;
        that.checkRegistered();
        let encState = await that.beldex.methods.getAccountState(that.account.publicKeySerialized()).call();
        var encAvailable = elgamal.unserialize(encState['y_available']);
        var encPending = elgamal.unserialize(encState['y_pending']);

        var guess = await that.getGuess();

        that.account.setAvailable(
            elgamal.decrypt(encAvailable, that.account.privateKey(), guess)
        );
        that.account.setPending(
            elgamal.decrypt(encPending, that.account.privateKey())
        );
        that.account._state.lastRollOver = await that.beldex.methods.last_roll_over(that.account.publicKeyHash()).call();
        that.account._state.nonceUsed = true;

        console.log("Account synchronized with contract: available = ", that.account.available(), ", pending = ", that.account.pending(), ", lastRollOver = ", that.account.lastRollOver());
    }

    /**
    [Transaction]
    Register a public/private key pair, stored in this client's Beldex account.
    This key pair is used for private interaction with the Beldex contract.
    NOTE: this key pair is NOT an Ethereum address, but instead, it should normally
    be used together with an Ethereum account address for the connection between
    Beldex and plain Ethereum token.

    @param secret The private key. If not given, then a new public/private key pair is
        generated, otherwise construct the public/private key pair form the secret.

    @return A promise that is resolved (or rejected) with the execution status of the
        registraction transaction.
    */
    async register (secret, registerGasLimit) {
        var that = this;
        if (secret === undefined) {
            that.account.keypair = utils.createAccount();
            that.account.aesKey = aes.generateKey();
        } else {
            that.account.keypair = utils.keyPairFromSecret(secret);
            that.account.aesKey = aes.generateKey(secret);
        }
        let isRegistered = await ClientBase.registered(that.beldex, that.account.publicKeySerialized());
        if (isRegistered) {
            // This branch would recover the account previously bound to the secret, and the corresponding balance.
            return await that.syncAccountState();
        } else {

            var [c, s] = utils.sign(that.beldex._address, that.account.keypair);
            if (registerGasLimit === undefined)
                registerGasLimit = 190000;
            let transaction = that.beldex.methods.register(that.account.publicKeySerialized(), c, s)
                .send({from: that.home, gas: registerGasLimit})
                .on('transactionHash', (hash) => {
                    console.log("Registration submitted (txHash = \"" + hash + "\").");
                })
                .on('receipt', (receipt) => {
                    console.log("Registration successful.");
                })
                .on('error', (error) => {
                    that.account.keypair = undefined;
                    console.log("Registration failed: " + error);
                });
            return transaction;
        }
    }

    async login(secret) {
      var that = this;
      if (secret === undefined) {
        that.account.keypair = utils.createAccount();
        that.account.aesKey = aes.generateKey();
      } else {
        that.account.keypair = utils.keyPairFromSecret(secret);
        that.account.aesKey = aes.generateKey(secret);
      }
      let isRegistered = await ClientBase.registered(
        that.beldex,
        that.account.publicKeySerialized(),
      );
      if (isRegistered) {
        // This branch would recover the account previously bound to the secret, and the corresponding balance.
        return await that.syncAccountState();
      } else {
        console.log('Login failed: this beldex account is not exists');
        return -1;
      }
    }

    /**
    [Transaction]
    Mint a given amount of tokens in the Beldex account.
    This essentially converts plain tokens to Beldex tokens that are encrypted in the Beldex contract.
    In other words, X tokens are deducted from this client's home account (Ethereum address), and X Beldex
    tokens are added to this client's Beldex account.

    The amount is represented in terms of a pre-defined unit. For example, if one unit represents 0.01 ETH,
    then an amount of 100 represents 1 ETH.

    @param value The amount to be minted into the Beldex account, in terms of unit.

    @return A promise that is resolved (or rejected) with the execution status of the mint transaction.
    */
    async mint (value) {
        throw new Error("Mint not implemented.");
    }


}

module.exports = ClientBase;