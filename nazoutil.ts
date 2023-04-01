import { Contract, JsonRpcProvider, keccak256, TransactionReceipt, Wallet } from "ethers"
import { abi } from './CTF.json'
import { groth16 } from 'snarkjs';
import { ArgumentParser } from 'argparse';
import 'dotenv/config'

const parser = new ArgumentParser({
  description: 'NAZO CTF Solver Tool',
  epilog: "Want to get flag? see https://www.youtube.com/watch?v=dQw4w9WgXcQ"
});
parser.add_argument('--provider', {
  default: 'https://rpc.ankr.com/eth_sepolia',
  help: 'Ethereum RPC provider',
})
parser.add_argument('--contract', {
  default: '0xb81bea2f2c5eb8a7f0027fd824fc806c5d769819',
  help: 'CTF contract address',
})
parser.add_argument('--type', {
  choices: ['validate', 'submit'],
  default: 'validate',
  help: 'validate or submit flag',
})
parser.add_argument('--challenge', {
  type: 'int',
  help: 'Challenge id',
})
parser.add_argument('--flag', {
  type: 'string',
  help: 'flag to validate or submit',
})
parser.add_argument('--private-key', {
  type: 'string',
  default: process.env.privateKey || ''
})

const args = parser.parse_args();
const provider = new JsonRpcProvider(args.provider)
const solver = new Wallet(args.private_key, provider)
const contract_addr = args.contract;
const contract = new Contract(contract_addr, abi, solver);

(async () => {
  const symbol = await contract.symbol()
  switch (args.type) {
    case 'validate': {
      try {
        const challenge_id = BigInt(args.challenge)
        const challenge = await contract.getChallenge(challenge_id)
        const [flagHashInChain, score, creator, solvedCount, status] = challenge
        console.log(`Challenge ${challenge_id} is created by [ ${creator} ] with score ${score}`)
        const flagHashInput = await flagHash(creator, args.flag)
        if (flagHashInChain == flagHashInput) {
          console.log("[✅] flag is correct")
        } else {
          console.log(`[❌] flag is incorrect`)
        }
      } catch (error) {
        console.log("getChallenge error", error)
      } finally {
        process.exit(0)
      }
    }
    case 'submit': {
      try {
        const challenge_id = BigInt(args.challenge)
        const challenge = await contract.getChallenge(challenge_id)
        const [_, score, creator, solvedCount, _status] = challenge
        const { proofs, status } = await generateProof(creator, solver.address, args.flag, contract)
        if (!status) {
          console.log("[❌] proof is incorrect")
          process.exit(0)
        }
        const tx = await contract.solveChallenge(challenge_id, proofs)
        const solved: TransactionReceipt = await tx.wait()
        if (!solved.status) {
          console.log("submit error", solved)
        }
        console.log(`[✅] Challenge ${challenge_id} solved, got ${score} ${symbol}\nTotal ${solvedCount + 1} solved)\nTransaction Hash: ${tx.hash}`)
      } catch (error) {
        console.log("submit error", error?.revert)
      } finally {
        process.exit(0)
      }
    }
  }
})()

export async function generateProof(challenge_creator: string, solver: string, password: string, contract: Contract): Promise<{
  status: boolean,
  proofs: string[]
}> {
  let payload = challenge_creator.toLowerCase() + password,
    passcode = BigInt(keccak256(Buffer.from(payload))),
    account = solver.toLowerCase(),
    accountBN = BigInt(account),
    secretBN = passcode - accountBN;

  let { proof, publicSignals } = await prove(accountBN, secretBN);
  let passcodeHashBN = BigInt(publicSignals[0]);
  let
    proofs = [proof.pi_a[0], proof.pi_a[1], proof.pi_b[0][1], proof.pi_b[0][0], proof.pi_b[1][1], proof.pi_b[1][0], proof.pi_c[0], proof.pi_c[1]]
  for (let i = 0; i < proofs.length; i++) {
    // string -> BN:
    proofs[i] = toHexString(BigInt(proofs[i]))
  }
  let r = await contract.verifyProof(
    [proofs[0], proofs[1]],
    [[proofs[2], proofs[3]], [proofs[4], proofs[5]]],
    [proofs[6], proofs[7]],
    [toHexString(passcodeHashBN), toHexString(accountBN)]
  );
  return {
    status: r,
    proofs
  };
}
export function toHexString(num: bigint) {
  return '0x' + BigInt(num).toString(16);
}
export async function flagHash(_account: string, pwd: any) {
  const account = _account.toLowerCase();
  const passcode = BigInt(keccak256(Buffer.from(`${account}${pwd}`)));
  let { proof, publicSignals } = await prove(BigInt('0'), passcode);
  const passcodeHash = BigInt(publicSignals[0]);
  return passcodeHash
}
export async function prove(addrBN: bigint, secretBN: bigint) {
  return await groth16.fullProve({ addr: addrBN.toString(), secret: secretBN.toString() }, "passcode_js/passcode.wasm", "passcode_js/passcode_0001.zkey");
}