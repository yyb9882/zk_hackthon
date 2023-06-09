const path = require("path");
const assert = require("chai").assert;
const wasm_tester = require("circom_tester").wasm;

describe("SHA256_2", () => {
    var circ_file = path.join(__dirname, "circuits", "SHA256_2.circom");
    var circ, num_constraints;

    before(async () => {
        circ = await wasm_tester(circ_file);
        await circ.loadConstraints();
    });

    // Compute hash of "abc" repetition without padding 
    // Input bits: 24 * 3 * 8
    it("should pass - small bitwidth", async () => {
        const input = {
            "M": [0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1,
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1,
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1, //abcabcabc (abc*3) 
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1,
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1,
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1, //abcabcabc (abc*3) 
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1,
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1,
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1, //abcabcabc (abc*3) 
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1,
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1,
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1, //abcabcabc (abc*3) 
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1,
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1,
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1, //abcabcabc (abc*3) 
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1,
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1,
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1, //abcabcabc (abc*3) 
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1,
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1,
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1, //abcabcabc (abc*3) 
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1,
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1,
                0,1,1,0,
                0,0,0,1,
                0,1,1,0,
                0,0,1,0,
                0,1,1,0,
                0,0,1,1, //abcabcabc (abc*3) 
            ]
        };
        const witness = await circ.calculateWitness(input);
        await circ.checkConstraints(witness);
        // Output: 
        // 99387e5a 8d4979fd d0a0bb1a 74d042e0 fdf56d90 9bacb32e 5c595e69 5a9c38b7
        await circ.assertOut(witness, {"final_hash": [125991561,1949098848,2422801197,105223881,3578045529,1355105186,3518866688,2848027893]});
    });
});