const ABICoder = require('web3-eth-abi');
const BN = require('bn.js');

const bn128 = require('../utils/bn128.js');
const utils = require('../utils/utils.js');
const { Convolver, FieldVector, FieldVectorPolynomial, GeneratorParams, GeneratorVector, PolyCommitment, Polynomial } = require('./algebra.js');
const InnerProductProver = require('./innerproduct.js');

class TransferProof {
    constructor() {
        this.serialize = () => { // please initialize this before calling this method...
            var result = "0x";
            result += bn128.representation(this.BA).slice(2);
            result += bn128.representation(this.BS).slice(2);
            result += bn128.representation(this.A).slice(2);
            result += bn128.representation(this.B).slice(2);

            this.CLnG.forEach((CLnG_k) => { result += bn128.representation(CLnG_k).slice(2); });
            this.CRnG.forEach((CRnG_k) => { result += bn128.representation(CRnG_k).slice(2); });
            this.C_0G.forEach((C_0G_k) => { result += bn128.representation(C_0G_k).slice(2); });
            this.DG.forEach((DG_k) => { result += bn128.representation(DG_k).slice(2); });
            this.y_0G.forEach((y_0G_k) => { result += bn128.representation(y_0G_k).slice(2); });
            this.gG.forEach((gG_k) => { result += bn128.representation(gG_k).slice(2); });
            this.C_XG.forEach((C_XG_k) => { result += bn128.representation(C_XG_k).slice(2); });
            this.y_XG.forEach((y_XG_k) => { result += bn128.representation(y_XG_k).slice(2); });
            this.f.getVector().forEach((f_k) => { result += bn128.bytes(f_k).slice(2); });

            result += bn128.bytes(this.z_A).slice(2);

            this.tCommits.getVector().forEach((commit) => {
                result += bn128.representation(commit).slice(2);
            });
            result += bn128.bytes(this.tHat).slice(2);
            result += bn128.bytes(this.mu).slice(2);

            result += bn128.bytes(this.c).slice(2);
            result += bn128.bytes(this.s_sk).slice(2);
            result += bn128.bytes(this.s_r).slice(2);
            result += bn128.bytes(this.s_b).slice(2);
            result += bn128.bytes(this.s_tau).slice(2);

            result += this.ipProof.serialize().slice(2);

            return result;
        }
    };
}

class TransferProver {
    constructor() {
        var params = new GeneratorParams(64);
        var ipProver = new InnerProductProver();

        var recursivePolynomials = (list, accum, a, b) => {
            // as, bs are log(N)-lengthed.
            // returns N-length list of coefficient vectors
            // should take about N log N to compute.
            if (a.length == 0) {
                list.push(accum.coefficients);
                return;
            }
            var aTop = a.pop();
            var bTop = b.pop();
            var left = new Polynomial([aTop.redNeg(), new BN(1).toRed(bn128.q).redSub(bTop)]);
            var right = new Polynomial([aTop, bTop]);
            recursivePolynomials(list, accum.mul(left), a, b);
            recursivePolynomials(list, accum.mul(right), a, b);
            a.push(aTop);
            b.push(bTop);
        }
    }
}

module.exports = TransferProver;
