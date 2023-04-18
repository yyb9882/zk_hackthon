const path = require("path");
const assert = require("chai").assert;
const wasm_tester = require("circom_tester").wasm;

describe("SHA256_1", () => {
    var circ_file = path.join(__dirname, "circuits", "SHA256_1.circom");
    var circ, num_constraints;

    before(async () => {
        circ = await wasm_tester(circ_file);
        await circ.loadConstraints();
    });

    // compute hash of "abc" without padding 
    it("should pass - small bitwidth", async () => {
        const input = {
            "M": [0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1
            ]
        };
        const witness = await circ.calculateWitness(input);
        await circ.checkConstraints(witness);
        // Output:
        // ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
        await circ.assertOut(witness, {"final_hash": [3128432319,2399260650,1094795486,1571693091,2953011619,2518121116,3021012833,4060091821]});
    });
});