const path = require("path");
const assert = require("chai").assert;
const wasm_tester = require("circom_tester").wasm;

describe("SHA256", () => {
    var circ_file = path.join(__dirname, "circuits", "SHA256.circom");
    var circ, num_constraints;

    before(async () => {
        circ = await wasm_tester(circ_file);
        await circ.loadConstraints();
    });

    // compute hash of "abc" with padding 
    it("should pass - small bitwidth", async () => {
        const input = {
            "M": [1633837952,0,0,0,0,0,0,0,0,0,0,0,0,0,0,24]
        };
        const witness = await circ.calculateWitness(input);
        await circ.checkConstraints(witness);
        // 32 bit NOT
        await circ.assertOut(witness, {"hash": [3128432319,2399260650,1094795486,1571693091,2953011619,2518121116,3021012833,4060091821]});
    });
});