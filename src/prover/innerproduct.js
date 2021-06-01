const ABICoder = require('web3-eth-abi');

const { GeneratorParams, FieldVector } = require('./algebra.js');
const bn128 = require('../utils/bn128.js');
const utils = require('../utils/utils.js');

class InnerProductProof {
    constructor() {
        this.serialize = () => {
            var result = "0x";
            this.L.forEach((l) => {
                result += bn128.representation(l).slice(2);
            });
            this.R.forEach((r) => {
                result += bn128.representation(r).slice(2);
            });
            result += bn128.bytes(this.a).slice(2);
            result += bn128.bytes(this.b).slice(2);
            return result;
        };
    }
}

module.exports = InnerProductProver;
