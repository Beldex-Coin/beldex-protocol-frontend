const bn128 = require('./bn128.js');
const crypto = require('crypto');
const BN = require('bn.js');
const ABICoder = require('web3-eth-abi');
const { soliditySha3 } = require('web3-utils');

const utils = {};


utils.randomUint256 = () => {
    return new BN(crypto.randomBytes(32), 16);
};

utils.createAccount = () => {
    var x = bn128.randomScalar();
    var y = bn128.curve.g.mul(x);
    return { 'x': x, 'y': y };
};

utils.keyPairFromSecret = (secret) => {
    var x = utils.hash(secret + "ETH"); 
    var y = bn128.curve.g.mul(x);
    return {'x': x, 'y': y}; 
};