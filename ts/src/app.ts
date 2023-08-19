import {base64} from '@scure/base'
import {randomBytes} from '@noble/hashes/utils'
import {secp256k1} from '@noble/curves/secp256k1'
import {sha256} from '@noble/hashes/sha256'
import {xchacha20} from '@noble/ciphers/chacha'

const utf8Decoder = new TextDecoder()

const utf8Encoder = new TextEncoder()

export const getSharedSecret = (privkey: string, pubkey: string): Uint8Array =>
  sha256(secp256k1.getSharedSecret(privkey, '02' + pubkey))
  // sha256(secp256k1.getSharedSecret(privkey, '02' + pubkey).subarray(1, 33))

export function encrypt(key: Uint8Array, text: string, v = 1) {
  if (v !== 1) {
    throw new Error('NIP44: unknown encryption version')
  }

  const nonce = randomBytes(24)
  const plaintext = utf8Encoder.encode(text)
  const ciphertext = xchacha20(key, nonce, plaintext)

  const payload = new Uint8Array(25 + ciphertext.length)
  payload.set([v], 0)
  payload.set(nonce, 1)
  payload.set(ciphertext, 25)

  return base64.encode(payload)
}

export function decrypt(key: Uint8Array, payload: string) {
  let data
  try {
    data = base64.decode(payload)
  } catch (e) {
    throw new Error(`NIP44: failed to base64 decode payload: ${e}`)
  }

  if (data[0] !== 1) {
    throw new Error(`NIP44: unknown encryption version: ${data[0]}`)
  }

  const nonce = data.slice(1, 25)
  const ciphertext = data.slice(25)
  const plaintext = xchacha20(key, nonce, ciphertext)

  return utf8Decoder.decode(plaintext)
}

// Convert a hex string to a byte array
function hexToBytes(hex) {
    let bytes = [];
    for (let c = 0; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}

// Convert a byte array to a hex string
function bytesToHex(bytes) {
    let hex = [];
    for (let i = 0; i < bytes.length; i++) {
        let current = bytes[i] < 0 ? bytes[i] + 256 : bytes[i];
        hex.push((current >>> 4).toString(16));
        hex.push((current & 0xF).toString(16));
    }
    return hex.join("");
}

const encrypted = "ARIfnWByZ3dkL9gihnkatNdGHJUC68u25qM="
const alice_priv = "0000000000000000000000000000000000000000000000000000000000000001";
const bob_priv = "0000000000000000000000000000000000000000000000000000000000000002";
const alice_pub = bytesToHex(secp256k1.getPublicKey(alice_priv)).substr(2, 64);
console.log("ALICE PUB = " + alice_pub);
const bob_pub = bytesToHex(secp256k1.getPublicKey(bob_priv)).substr(2, 64);
console.log("BOB PUB = " + bob_pub);
let key = getSharedSecret(alice_priv, bob_pub);
console.log("SHARED = " + bytesToHex(key));
let key2 = getSharedSecret(bob_priv, alice_pub);
console.log("SHARED = " + bytesToHex(key2));
let decrypted = decrypt(key, encrypted);
console.log("DECRYPTED: " + decrypted);
console.log("DECRYPTED HEX: " + bytesToHex(decrypted));
