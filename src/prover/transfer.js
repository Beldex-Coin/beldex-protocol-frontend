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

        this.generateProof = (statement, witness) => {
            var proof = new TransferProof();

            var statementHash = utils.hash(ABICoder.encodeParameters([
                'bytes32[2][]',
                'bytes32[2][]',
                'bytes32[2][]',
                'bytes32[2]',
                'bytes32[2][]',
                'uint256',
            ], [
                statement['CLn'].map(bn128.serialize),
                statement['CRn'].map(bn128.serialize),
                statement['C'].map(bn128.serialize),
                bn128.serialize(statement['D']),
                statement['y'].map(bn128.serialize),
                statement['epoch'],
            ]));

            statement['CLn'] = new GeneratorVector(statement['CLn']);
            statement['CRn'] = new GeneratorVector(statement['CRn']);
            statement['C'] = new GeneratorVector(statement['C']);
            statement['y'] = new GeneratorVector(statement['y']);

            witness['bTransfer'] = new BN(witness['bTransfer']).toRed(bn128.q);
            witness['bDiff'] = new BN(witness['bDiff']).toRed(bn128.q);

            var number = witness['bTransfer'].add(witness['bDiff'].shln(32)); // shln a red? check
            var aL = new FieldVector(number.toString(2, 64).split("").reverse().map((i) => new BN(i, 2).toRed(bn128.q)));
            var aR = aL.plus(new BN(1).toRed(bn128.q).redNeg());
            var alpha = bn128.randomScalar();
            proof.BA = params.commit(alpha, aL, aR);
            var sL = new FieldVector(Array.from({ length: 64 }).map(bn128.randomScalar));
            var sR = new FieldVector(Array.from({ length: 64 }).map(bn128.randomScalar));
            var rho = bn128.randomScalar(); // already reduced
            proof.BS = params.commit(rho, sL, sR);

            var N = statement['y'].length();
            if (N & (N - 1))
                throw "Size must be a power of 2!"; // probably unnecessary... this won't be called directly.
            var m = new BN(N).bitLength() - 1; // assuming that N is a power of 2?
            // DON'T need to extend the params anymore. 64 will always be enough.
            var r_A = bn128.randomScalar();
            var r_B = bn128.randomScalar();
            var a = new FieldVector(Array.from({ length: 2 * m }).map(bn128.randomScalar));
            var b = new FieldVector((new BN(witness['index'][1]).toString(2, m) + new BN(witness['index'][0]).toString(2, m)).split("").reverse().map((i) => new BN(i, 2).toRed(bn128.q)));
            var c = a.hadamard(b.times(new BN(2).toRed(bn128.q)).negate().plus(new BN(1).toRed(bn128.q))); // check this
            var d = a.hadamard(a).negate();
            var e = new FieldVector([a.getVector()[0].redMul(a.getVector()[m]), a.getVector()[0].redMul(a.getVector()[m])]);
            var f = new FieldVector([a.getVector()[b.getVector()[0].toNumber() * m], a.getVector()[b.getVector()[m].toNumber() * m].redNeg()]);

            proof.A = params.commit(r_A, a.concat(d).concat(e));
            proof.B = params.commit(r_B, b.concat(c).concat(f));

            var v = utils.hash(ABICoder.encodeParameters([
                'bytes32',
                'bytes32[2]',
                'bytes32[2]',
                'bytes32[2]',
                'bytes32[2]',
            ], [
                bn128.bytes(statementHash),
                bn128.serialize(proof.BA),
                bn128.serialize(proof.BS),
                bn128.serialize(proof.A),
                bn128.serialize(proof.B),
            ]));

            var phi = Array.from({ length: m }).map(bn128.randomScalar);
            var chi = Array.from({ length: m }).map(bn128.randomScalar);
            var psi = Array.from({ length: m }).map(bn128.randomScalar);
            var omega = Array.from({ length: m }).map(bn128.randomScalar);

            var P = [];
            var Q = [];
            recursivePolynomials(P, new Polynomial(), a.getVector().slice(0, m), b.getVector().slice(0, m));
            recursivePolynomials(Q, new Polynomial(), a.getVector().slice(m), b.getVector().slice(m));
            P = Array.from({ length: m }).map((_, k) => new FieldVector(P.map((P_i) => P_i[k])));
            Q = Array.from({ length: m }).map((_, k) => new FieldVector(Q.map((Q_i) => Q_i[k])));

            proof.CLnG = Array.from({ length: m }).map((_, k) => statement['CLn'].commit(P[k]).add(statement['y'].getVector()[witness['index'][0]].mul(phi[k])));
            proof.CRnG = Array.from({ length: m }).map((_, k) => statement['CRn'].commit(P[k]).add(params.getG().mul(phi[k])));
            proof.C_0G = Array.from({ length: m }).map((_, k) => statement['C'].commit(P[k]).add(statement['y'].getVector()[witness['index'][0]].mul(chi[k])));
            proof.DG = Array.from({ length: m }).map((_, k) => params.getG().mul(chi[k]));
            proof.y_0G = Array.from({ length: m }).map((_, k) => statement['y'].commit(P[k]).add(statement['y'].getVector()[witness['index'][0]].mul(psi[k])));
            proof.gG = Array.from({ length: m }).map((_, k) => params.getG().mul(psi[k]));
            proof.C_XG = Array.from({ length: m }).map((_, k) => statement['D'].mul(omega[k]));
            proof.y_XG = Array.from({ length: m }).map((_, k) => params.getG().mul(omega[k]));
            var vPow = new BN(1).toRed(bn128.q);
            for (var i = 0; i < N; i++) { // could turn this into a complicated reduce, but...
                var temp = params.getG().mul(witness['bTransfer'].redMul(vPow));
                var poly = i % 2 ? Q : P; // clunky, i know, etc. etc.
                proof.C_XG = proof.C_XG.map((C_XG_k, k) => C_XG_k.add(temp.mul(poly[k].getVector()[(witness['index'][0] + N - (i - i % 2)) % N].redNeg().redAdd(poly[k].getVector()[(witness['index'][1] + N - (i - i % 2)) % N]))));
                if (i != 0)
                    vPow = vPow.redMul(v);
            }

            var w = utils.hash(ABICoder.encodeParameters([
                'bytes32',
                'bytes32[2][]',
                'bytes32[2][]',
                'bytes32[2][]',
                'bytes32[2][]',
                'bytes32[2][]',
                'bytes32[2][]',
                'bytes32[2][]',
                'bytes32[2][]',
            ], [
                bn128.bytes(v),
                proof.CLnG.map(bn128.serialize),
                proof.CRnG.map(bn128.serialize),
                proof.C_0G.map(bn128.serialize),
                proof.DG.map(bn128.serialize),
                proof.y_0G.map(bn128.serialize),
                proof.gG.map(bn128.serialize),
                proof.C_XG.map(bn128.serialize),
                proof.y_XG.map(bn128.serialize),
            ]));

            proof.f = b.times(w).add(a);
            proof.z_A = r_B.redMul(w).redAdd(r_A);

            var y = utils.hash(ABICoder.encodeParameters([
                'bytes32',
            ], [
                bn128.bytes(w), // that's it?
            ]));

            var ys = [new BN(1).toRed(bn128.q)];
            for (var i = 1; i < 64; i++) { // it would be nice to have a nifty functional way of doing this.
                ys.push(ys[i - 1].redMul(y));
            }
            ys = new FieldVector(ys); // could avoid this line by starting ys as a fieldvector and using "plus". not going to bother.
            var z = utils.hash(bn128.bytes(y));
            var zs = [z.redPow(new BN(2)), z.redPow(new BN(3))];
            var twos = [new BN(1).toRed(bn128.q)];
            for (var i = 1; i < 32; i++) {
                twos.push(twos[i - 1].redMul(new BN(2).toRed(bn128.q)));
            }
            var twoTimesZs = [];
            for (var i = 0; i < 2; i++) {
                for (var j = 0; j < 32; j++) {
                    twoTimesZs.push(zs[i].redMul(twos[j]));
                }
            }
            twoTimesZs = new FieldVector(twoTimesZs);
            var lPoly = new FieldVectorPolynomial(aL.plus(z.redNeg()), sL);
            var rPoly = new FieldVectorPolynomial(ys.hadamard(aR.plus(z)).add(twoTimesZs), sR.hadamard(ys));
            var tPolyCoefficients = lPoly.innerProduct(rPoly); // just an array of BN Reds... should be length 3
            var polyCommitment = new PolyCommitment(params, tPolyCoefficients);
            proof.tCommits = new GeneratorVector(polyCommitment.getCommitments()); // just 2 of them

            var x = utils.hash(ABICoder.encodeParameters([
                'bytes32',
                'bytes32[2]',
                'bytes32[2]',
            ], [
                bn128.bytes(z),
                ...polyCommitment.getCommitments().map(bn128.serialize),
            ]));

            var evalCommit = polyCommitment.evaluate(x);
            proof.tHat = evalCommit.getX();
            var tauX = evalCommit.getR(); // no longer public...
            proof.mu = alpha.redAdd(rho.redMul(x));

            var CRnR = bn128.zero;
            var y_0R = bn128.zero;
            var y_XR = bn128.zero;
            var DR = bn128.zero;
            var gR = bn128.zero;
            var p = new FieldVector(Array.from({ length: N }).map(() => new BN().toRed(bn128.q))); // evaluations of poly_0 and poly_1 at w.
            var q = new FieldVector(Array.from({ length: N }).map(() => new BN().toRed(bn128.q))); // verifier will compute these using f.

        }
    }
}

module.exports = TransferProver;
