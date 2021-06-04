const ABICoder = require('web3-eth-abi');
const BN = require('bn.js');

const bn128 = require('../utils/bn128.js');
const utils = require('../utils/utils.js');
const { GeneratorParams, GeneratorVector, FieldVector, FieldVectorPolynomial, PolyCommitment } = require('./algebra.js');
const InnerProductProver = require('./innerproduct.js');

class RedeemProof {
    constructor() {
        this.serialize = () => { // please initialize this before calling this method...
            var result = "0x";
            result += bn128.representation(this.BA).slice(2);
            result += bn128.representation(this.BS).slice(2);

            this.tCommits.getVector().forEach((commit) => {
                result += bn128.representation(commit).slice(2);
            });
            result += bn128.bytes(this.tHat).slice(2);
            result += bn128.bytes(this.mu).slice(2);

            result += bn128.bytes(this.c).slice(2);
            result += bn128.bytes(this.s_sk).slice(2);
            result += bn128.bytes(this.s_b).slice(2);
            result += bn128.bytes(this.s_tau).slice(2);

            result += this.ipProof.serialize().slice(2);

            return result;
        }
    };
}


class RedeemProver {
    constructor() {
        var params = new GeneratorParams(32);
        var ipProver = new InnerProductProver();

        this.generateProof = (statement, witness) => { // salt probably won't be used
            var proof = new RedeemProof();

            var statementHash = utils.hash(ABICoder.encodeParameters([
                'bytes32[2]',
                'bytes32[2]',
                'bytes32[2]',
                'uint256',
                'address',
            ], [
                statement['CLn'],
                statement['CRn'],
                statement['y'],
                statement['epoch'],
                statement['sender'],
            ])); // useless to break this out up top. "psychologically" easier

            statement['CLn'] = bn128.unserialize(statement['CLn']);
            statement['CRn'] = bn128.unserialize(statement['CRn']);
            statement['y'] = bn128.unserialize(statement['y']);
            witness['bDiff'] = new BN(witness['bDiff']).toRed(bn128.q);

            var aL = new FieldVector(witness['bDiff'].toString(2, 32).split("").reverse().map((i) => new BN(i, 2).toRed(bn128.q)));
            var aR = aL.plus(new BN(1).toRed(bn128.q).redNeg());
            var alpha = bn128.randomScalar();
            proof.BA = params.commit(alpha, aL, aR);
            var sL = new FieldVector(Array.from({ length: 32 }).map(bn128.randomScalar));
            var sR = new FieldVector(Array.from({ length: 32 }).map(bn128.randomScalar));
            var rho = bn128.randomScalar(); // already reduced
            proof.BS = params.commit(rho, sL, sR);

        }
    }
}

module.exports = RedeemProver;

