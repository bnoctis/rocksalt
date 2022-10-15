import s from 'libsodium-wrappers'
import { Buffer } from 'buffer/'

await s.ready

type BufferLike = Buffer | string

export const KEY_BYTES = s.crypto_secretbox_KEYBYTES
export const SECRET_KEY_BYTES = s.crypto_box_SECRETKEYBYTES
export const PUBLIC_KEY_BYTES = s.crypto_box_PUBLICKEYBYTES
export const SIGNING_SECRET_KEY_BYTES = s.crypto_sign_SECRETKEYBYTES
export const SIGNING_PUBLIC_KEY_BYTES = s.crypto_sign_PUBLICKEYBYTES
export const PUBLICKEY_NONCE_BYTES = s.crypto_box_NONCEBYTES
export const SYMMETRIC_NONCE_BYTES = s.crypto_secretbox_NONCEBYTES

type KeyUsage = 'encryption' | 'signing'

export interface ExportedKey {
	publicKey: string
	privateKey: string
	keyType: s.KeyType
	usage: KeyUsage
}

export class KeyPair {
	// @ts-ignore TS2564
	publicKey: Buffer
	// @ts-ignore TS2564
	privateKey: Buffer
	// @ts-ignore TS2564
	keyType: s.KeyType
	// @ts-ignore TS2564
	usage: KeyUsage

	public static generateEncryption() {
		const {publicKey, privateKey, keyType} = s.crypto_box_keypair()
		const kp = new KeyPair
		kp.publicKey = Buffer.from(publicKey)
		kp.privateKey = Buffer.from(privateKey)
		kp.keyType = keyType
		kp.usage = 'encryption'
		return kp
	}

	static generateSigning() {
		// TODO: support seed?
		const {publicKey, privateKey, keyType} = s.crypto_sign_keypair()
		const kp = new KeyPair
		kp.publicKey = Buffer.from(publicKey)
		kp.privateKey = Buffer.from(privateKey)
		kp.keyType = keyType
		kp.usage = 'signing'
		return kp
	}

	static import(exported: ExportedKey) {
		const kp = new KeyPair 
		kp.privateKey = Buffer.from(s.from_base64(exported.privateKey))
		kp.publicKey = Buffer.from(s.from_base64(exported.publicKey))
		kp.keyType = exported.keyType
		kp.usage = exported.usage
		return kp
	}

	export(): ExportedKey {
		return {
			publicKey: s.to_base64(this.publicKey),
			privateKey: s.to_base64(this.privateKey),
			keyType: this.keyType,
			usage: this.usage,
		}
	}
}

function ensureBuffer(bufLike: BufferLike) {
	if(!(bufLike instanceof Buffer)) {
		bufLike = Buffer.from(bufLike)
	}
	return bufLike
}

function ensurePrivateKey(key: KeyPair | BufferLike) {
	if(key instanceof KeyPair) {
		key = key.privateKey
	}
	return ensureBuffer(key)
}

function ensurePublicKey(key: KeyPair | BufferLike) {
	if(key instanceof KeyPair) {
		key = key.publicKey
	}
	return ensureBuffer(key)
}

function ensureEncryptionKey(key: KeyPair) {
	if(key.usage !== 'encryption') {
		throw 'must use encryption key'
	}
}

function ensureSigningKey(key: KeyPair) {
	if(key.usage !== 'signing') {
		throw 'must use signing key'
	}
}

/* section: random */

export function random() {
	return s.randombytes_random()
}

export function randomUniform(max: number) {
	return s.randombytes_uniform(max)
}

export function randomBytes(length: number) {
	return Buffer.from(s.randombytes_buf(length))
}

/* section: pwhash */

export const PWHASH_BYTES_MIN = s.crypto_pwhash_BYTES_MIN
export const PWHASH_OPSLIMIT_MIN = s.crypto_pwhash_OPSLIMIT_MIN
export const PWHASH_MEMLIMIT_MIN = s.crypto_pwhash_MEMLIMIT_MIN
export const PWHASH_SALT_BYTES = s.crypto_pwhash_SALTBYTES

export enum PwhashOpsLimit {
	Interactive = s.crypto_pwhash_OPSLIMIT_INTERACTIVE,
	Moderate = s.crypto_pwhash_OPSLIMIT_MODERATE,
	Sensitive = s.crypto_pwhash_OPSLIMIT_SENSITIVE,
}

export enum PwhashMemLimit {
	Interactive = s.crypto_pwhash_MEMLIMIT_INTERACTIVE,
	Moderate = s.crypto_pwhash_MEMLIMIT_MODERATE,
	Sensitive = s.crypto_pwhash_MEMLIMIT_SENSITIVE,
}

export enum PwhashAlg {
	Default = s.crypto_pwhash_ALG_DEFAULT,
	Argon2i13 = s.crypto_pwhash_ALG_ARGON2I13,
	Argon2id13 = s.crypto_pwhash_ALG_ARGON2ID13,
}

export interface PwhashParams {
	password: string,
	salt?: BufferLike,
	outLen?: number,
	opsLimit?: PwhashOpsLimit | number,
	memLimit?: PwhashMemLimit | number,
	alg?: PwhashAlg,
	stored?: boolean,
}

export const PWHASH_PARAMS_DEFAULT: PwhashParams = {
	password: '',
	outLen: PWHASH_BYTES_MIN * 2,
	opsLimit: PwhashOpsLimit.Moderate,
	memLimit: PwhashMemLimit.Moderate,
	alg: PwhashAlg.Default,
	stored: true,
}

export function pwhashSalt() {
	return randomBytes(PWHASH_SALT_BYTES)
}

export function pwhash(params: PwhashParams): BufferLike {
	const {password, outLen, opsLimit, memLimit, alg, stored}: PwhashParams = Object.assign({}, PWHASH_PARAMS_DEFAULT, params)
	let salt = params.salt

	if(!stored) {
		if(salt === undefined) {
			throw 'salt must be set if not generating stored string'
		}
		salt = ensureBuffer(salt)
		if(salt.byteLength !== PWHASH_SALT_BYTES) {
			throw `salt byteLength must be PWHASH_SALT_BYTES`
		}

		// @ts-ignore T2532 covered by Object.assign at beginning of function
		if(outLen < PWHASH_BYTES_MIN) {
			throw `outLen must be >= PWHASH_BYTES_MIN`
		}

		// @ts-ignore T2532
		if(opsLimit < PWHASH_OPSLIMIT_MIN) {
			throw `opsLimit must be >= PWHASH_OPSLIMIT_MIN`
		}

		// @ts-ignore T2532
		if(memLimit < PWHASH_MEMLIMIT_MIN) {
			throw `memLimit must be >= PWHASH_MEMLIMIT_MIN`
		}
	}

	return stored
		? s.crypto_pwhash_str(password, opsLimit as number, memLimit as number)
		: Buffer.from(s.crypto_pwhash(outLen as number, password, salt as Buffer, opsLimit as number, memLimit as number, alg as number))
}

export function pwhashVerify({ hashed, password }: { hashed: string, password: BufferLike }) {
	password = ensureBuffer(password)
	return s.crypto_pwhash_str_verify(hashed, password)
}

/* section: encryption & decryption */

export type NonceType = 'symmetric' | 'publickey'
const NONCE_BYTES_MAP = {
	'symmetric': SYMMETRIC_NONCE_BYTES,
	'publickey': PUBLICKEY_NONCE_BYTES,
}

function passwordKey(password: string, nonce: Buffer) {
	return pwhash({
		password,
		salt: nonce.slice(0, PWHASH_SALT_BYTES),
		outLen: KEY_BYTES,
		stored: false,
	}) as Buffer
}

export function generateKey() {
	return Buffer.from(s.crypto_secretbox_keygen())
}

export function generateNonce(type: NonceType) {
	return randomBytes(NONCE_BYTES_MAP[type])
}

interface EncryptParamsCommon {
	message: BufferLike,
	nonce?: Buffer,
	detached?: boolean,
}
interface EncryptParamsPassword {
	password: string,
	key?: never, sender?: never, recipient?: never,
}
interface EncryptParamsSymmetricKey {
	key: Buffer,
	password?: never, sender?: never, recipient?: never,
}
interface EncryptParamsPublicKey {
	sender: KeyPair,
	recipient: KeyPair | Buffer,
	password?: never, key?: never,
}
export type EncryptParams = EncryptParamsCommon & (EncryptParamsPassword | EncryptParamsSymmetricKey | EncryptParamsPublicKey)

export interface Encrypted {
	ciphertext: Buffer,
	nonce: Buffer,
	authTag?: Buffer,
}

export function encrypt(params: EncryptParams): Encrypted {
	const message = ensureBuffer(params.message)
	const nonce = params.nonce === undefined
		? generateNonce(params.password !== undefined ? 'symmetric' : 'publickey')
		: ensureBuffer(params.nonce)

	if(params.sender !== undefined) {
		// public-key encryption
		ensureEncryptionKey(params.sender)
		const sender = ensurePrivateKey(params.sender)
		const recipient = ensurePublicKey(params.recipient)

		if(params.detached) {
			const { ciphertext, mac } = s.crypto_box_detached(message, nonce, recipient, sender)
			return { ciphertext: Buffer.from(ciphertext), nonce, authTag: Buffer.from(mac) }
		} else {
			return { ciphertext: Buffer.from(s.crypto_box_easy(message, nonce, recipient, sender)), nonce }
		}
	} else {
		// symmetric encryption
		const key = params.password === undefined ? params.key : passwordKey(params.password, nonce)

		if(params.detached) {
			const { cipher, mac } = s.crypto_secretbox_detached(message, nonce, key)
			return { ciphertext: Buffer.from(cipher), nonce, authTag: Buffer.from(mac) }
		} else {
			return { ciphertext: Buffer.from(s.crypto_secretbox_easy(message, nonce, key)), nonce }
		}
	}
}

interface DecryptParamsPublicKey {
	sender: KeyPair | Buffer,
	recipient: KeyPair,
	password?: never, key?: never,
}
export type DecryptParams = Encrypted & (EncryptParamsPassword | EncryptParamsSymmetricKey | DecryptParamsPublicKey)

export function decrypt(params: DecryptParams) {
	const ciphertext = ensureBuffer(params.ciphertext)
	const nonce = ensureBuffer(params.nonce)

	if(params.sender !== undefined) {
		// public-key decryption
		ensureEncryptionKey(params.recipient)
		const sender = ensurePublicKey(params.sender)
		const recipient = ensurePrivateKey(params.recipient)

		return Buffer.from(params.authTag === undefined
			? s.crypto_box_open_easy(ciphertext, nonce, sender, recipient)
			: s.crypto_box_open_detached(ciphertext, params.authTag, nonce, sender, recipient))
	} else {
		// symmetric decryption
		const key = params.password === undefined ? params.key : passwordKey(params.password, nonce)
		
		return Buffer.from(params.authTag === undefined
			? s.crypto_secretbox_open_easy(ciphertext, nonce, key)
			: s.crypto_secretbox_open_detached(ciphertext, params.authTag, nonce, key))
	}
}

/* section: sign & verify */

export interface SignParams {
	message: BufferLike,
	key: KeyPair,
	detached?: boolean,
}

export function sign({ message, key, detached }: SignParams) {
	ensureSigningKey(key)
	return Buffer.from((detached ? s.crypto_sign_detached : s.crypto_sign)(message, ensurePrivateKey(key)))
}

export interface VerifyParams {
	message: BufferLike,
	key: KeyPair | BufferLike,
	sig?: Buffer,
}

export function verify({ message, key, sig }: VerifyParams): Buffer | boolean {
	if(key instanceof KeyPair) {
		ensureSigningKey(key)
	}
	key = ensurePublicKey(key)
	return sig === undefined
		? Buffer.from(s.crypto_sign_open(message, key))
		: s.crypto_sign_verify_detached(sig, message, key)
}

export class MultiPartSign {
	state: s.StateAddress

	constructor() {
		this.state = s.crypto_sign_init()
	}

	update(chunk: BufferLike) {
		s.crypto_sign_update(this.state, ensureBuffer(chunk))
		return this
	}

	sign(privateKey: KeyPair) {
		return Buffer.from(s.crypto_sign_final_create(this.state, ensurePrivateKey(privateKey)))
	}

	verify(sig: Buffer, publicKey: KeyPair | BufferLike) {
		return s.crypto_sign_final_verify(this.state, sig, ensurePublicKey(publicKey))
	}
}

export function mpsign() {
	return new MultiPartSign
}

/* section: seal & open seal */

export interface SealParams {
	message: BufferLike,
	recipient: KeyPair | BufferLike,
}

export function seal({ message, recipient }: SealParams) {
	return Buffer.from(s.crypto_box_seal(ensureBuffer(message), ensurePublicKey(recipient)))
}

export interface OpenSealParams {
	sealed: BufferLike,
	recipient: KeyPair,
}

export function openSeal({ sealed, recipient }: OpenSealParams) {
	ensureEncryptionKey(recipient)
	return Buffer.from(s.crypto_box_seal_open(sealed, recipient.publicKey, recipient.privateKey))
}

