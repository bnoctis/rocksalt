import * as rs from './lib'
import test from 'ava'

test('generate keypairs', t => {
	rs.KeyPair.generateEncryption()
	rs.KeyPair.generateSigning()
	t.pass()
})

test('keypair export and import', t => {
	const kp = rs.KeyPair.generateEncryption()
	const imp = rs.KeyPair.import(kp.export())
	t.assert(kp.privateKey.equals(imp.privateKey))
	t.assert(kp.publicKey.equals(imp.publicKey))
})

test('pwhash not stored', t => {
	rs.pwhash({ password: 'password', salt: rs.pwhashSalt() })
	t.pass()
})

test('pwhash stored and verify', t => {
	const pwhs = rs.pwhash({ password: 'password', stored: true }) as string
	t.assert(rs.pwhashVerify({ hashed: pwhs, password: 'password' }))
})

test('encrypt and decrypt, password, combined', t => {
	const message = (new Date).toISOString()
	const encrypted = rs.encrypt({ message, password: 'password' })
	t.is(rs.decrypt({ ...encrypted, password: 'password' }).toString(), message)
})

test('encrypt and decrypt, password, detached', t => {
	const message = (new Date).toISOString()
	const encrypted = rs.encrypt({ message, password: 'password', detached: true })
	t.is(rs.decrypt({ ...encrypted, password: 'password' }).toString(), message)
})

test('encrypt and decrypt, symmetric, combined', t => {
	const message = (new Date).toISOString()
	const key = rs.generateKey()
	const encrypted = rs.encrypt({ message, key })
	t.is(rs.decrypt({ ...encrypted, key }).toString(), message)
})

test('encrypt and decrypt, symmetric, detached', t => {
	const message = (new Date).toISOString()
	const key = rs.generateKey()
	const encrypted = rs.encrypt({ message, key, detached: true })
	t.is(rs.decrypt({ ...encrypted, key }).toString(), message)
})

test('encrypt and decrypt, public-key, combined', t => {
	const message = (new Date).toISOString()
	const alice = rs.KeyPair.generateEncryption()
	const bob = rs.KeyPair.generateEncryption()
	const encrypted = rs.encrypt({ message, sender: alice, recipient: bob })
	t.is(rs.decrypt({ ...encrypted, sender: alice, recipient: bob }).toString(), message)
})

test('encrypt and decrypt, public-key, detached', t => {
	const message = (new Date).toISOString()
	const alice = rs.KeyPair.generateEncryption()
	const bob = rs.KeyPair.generateEncryption()
	const encrypted = rs.encrypt({ message, sender: alice, recipient: bob, detached: true })
	t.is(rs.decrypt({ ...encrypted, sender: alice, recipient: bob }).toString(), message)
})

test('sign and verify, combined', t => {
	const key = rs.KeyPair.generateSigning()
	const signed = rs.sign({ message: (new Date).toISOString(), key })
	t.assert(rs.verify({ message: signed, key }))
})

test('sign and verify, detached', t => {
	const message = (new Date).toISOString()
	const key = rs.KeyPair.generateSigning()
	const sig = rs.sign({ message, key, detached: true })
	t.assert(rs.verify({ message, key, sig }))
})

test('seal and open seal', t => {
	const recipient = rs.KeyPair.generateEncryption()

	const message = (new Date).toISOString()
	const sealed = rs.seal({ message, recipient })
	t.is(rs.openSeal({ sealed, recipient }).toString(), message)
})

