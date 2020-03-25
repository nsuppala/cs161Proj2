package proj2

// CS 161 Project 2 Spring 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username string

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)

	PublicKey     userlib.DSVerifyKey
	PrivateKey    userlib.DSSignKey
	Files         map[string]FileAccess // Map from filenames to a FileAccess
	UUID          uuid.UUID
	EncryptionKey []byte
	MACKey        []byte
}

// Structure definition for a node in the sharing tree
// All field are for the parent FileAccess or the FilePrologue
type FileAccess struct {
	UUID          uuid.UUID
	EncryptionKey []byte
	MACKey        []byte
}

// The structure for file's data
// Sink node in the sharing tree
type FilePrologue struct {
	UUID            uuid.UUID
	Owner           uuid.UUID             // Owner's UUID ion datastore server
	ContentSegments []uuid.UUID           // Slice of UUIDs to FileContents parts in order
	SharedWith      map[string]FileAccess // Map of usernames to the FileAccess issued to them (only tracks direct shares by owner)
}

// The structure for file
type FileContents struct {
	UUID uuid.UUID
	Data []byte
}

// Helper functions

// Encrypts plaintext data, MACs the encryption, and concetantes them to store on datastore
func SecureAndStore(encKey []byte, macKey []byte, ID uuid.UUID, marshalData []byte) {
	iv := userlib.RandomBytes(16)
	encData := userlib.SymEnc(encKey[:16], iv, marshalData)
	macData, _ := userlib.HMACEval(macKey[:16], encData)
	data := append(encData, macData...)
	userlib.DatastoreSet(ID, data)
}

// Retrieves an entry on datastore if it exists, verifies its integrity, and decrypts the ciphertext
func VerifyAndDecrypt(decKey []byte, macKey []byte, ID uuid.UUID) ([]byte, error) {
	data, ok := userlib.DatastoreGet(ID)
	if !ok {
		return nil, errors.New(strings.ToTitle("No entry exists in datastore at UUID"))
	} else {
		encData := data[:(len(data) - userlib.HashSize)]
		macData := data[(len(data) - userlib.HashSize):]
		macCheck, _ := userlib.HMACEval(macKey[:16], encData)
		if !userlib.HMACEqual(macData, macCheck) {
			return nil, errors.New(strings.ToTitle("Incorrect password/keys or compromised data"))
		}
		return userlib.SymDec(decKey[:16], encData), nil
	}
}

// Generates random encryption and MAC keys
func GenRandEncMacKeys() (encKey, macKey []byte) {
	randKey := userlib.RandomBytes(16)
	encKey, _ = userlib.HashKDF(randKey, []byte("encryption"))
	macKey, _ = userlib.HashKDF(randKey, []byte("MAC"))
	return
}

func getFilePrologue(userdata *User, filename string) (FilePrologue, error) {
	// get FileAccess
	access, ok := userdata.Files[filename]
	if !ok {
		return FilePrologue{}, errors.New(strings.ToTitle("File does not exist"))
	}

	// get FilePrologue
	prologueID := access.UUID
	decryptedPrologue, err := VerifyAndDecrypt(access.EncryptionKey, access.MACKey, prologueID)
	if err != nil {
		return FilePrologue{}, errors.New(strings.ToTitle("FilePrologue has been compromised"))
	}
	prologue := FilePrologue{}
	json.Unmarshal(decryptedPrologue, &prologue)

	return prologue, nil
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing
// hashes of common passwords downloaded from the internet.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// Generate public key for username and add it to the keystore
	// add privatekey to userdata struct
	userdata.Username = username
	_, ok := userlib.KeystoreGet(username)
	if ok {
		return nil, errors.New(strings.ToTitle("Entry already exists in keystore for" + username))
	}
	userdata.PrivateKey, userdata.PublicKey, _ = userlib.DSKeyGen()
	userlib.KeystoreSet(username, userdata.PublicKey)

	// initialize empty userfiles map
	userdata.Files = make(map[string]FileAccess)

	// use password to generate symmetric key with public key as salt
	salt, _ := json.Marshal(userdata.PublicKey)
	kp := userlib.Argon2Key([]byte(password), salt, 16)

	// use kp to generate other keys
	usernameHashKey, _ := userlib.HashKDF(kp, []byte("username hash"))
	macKey, _ := userlib.HashKDF(kp, []byte("MAC"))
	encKey, _ := userlib.HashKDF(kp, []byte("encryption"))
	userdata.MACKey, userdata.EncryptionKey = macKey, encKey

	// generate UUID from username and HMAC_usernameHashKey
	hmac_username, _ := userlib.HMACEval(usernameHashKey[:16], []byte(username))
	userdata.UUID, _ = uuid.FromBytes(hmac_username)

	// generate encrypted userdata and store in DataStore
	marshalData, _ := json.Marshal(userdata)
	SecureAndStore(encKey, macKey, userdata.UUID, marshalData)

	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// get public key and check that it exists in keystore
	pubkey, ok := userlib.KeystoreGet(username)
	if !ok {
		return nil, errors.New(strings.ToTitle("Entry does not exist in keystore for" + username))
	}

	// generate kp to verify signature
	salt, _ := json.Marshal(pubkey)
	kp := userlib.Argon2Key([]byte(password), salt, 16)

	// use kp to generate other keys
	usernameHashKey, _ := userlib.HashKDF(kp, []byte("username hash"))
	macKey, _ := userlib.HashKDF(kp, []byte("MAC"))
	encKey, _ := userlib.HashKDF(kp, []byte("encryption"))

	// generate UUID from username and HMAC_usernameHashKey
	hmac_username, _ := userlib.HMACEval(usernameHashKey[:16], []byte(username))
	uuid1, _ := uuid.FromBytes(hmac_username)

	// check to see if uuid exists in datastore
	// verify, decrypt, and unmarshal
	decData, err := VerifyAndDecrypt(encKey, macKey, uuid1)
	if err != nil {
		return nil, errors.New(strings.ToTitle("Password incorrect or data compromised"))
	}
	json.Unmarshal(decData, &userdata)

	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	// If file already exists for user, overwrite it
	access, ok := userdata.Files[filename]
	if ok {
		// Edit and reupload FilePrologue
		prologueID := access.UUID
		decryptedPrologue, err := VerifyAndDecrypt(access.EncryptionKey, access.MACKey, prologueID)
		if err != nil {
			return
		}
		prologue := FilePrologue{}
		json.Unmarshal(decryptedPrologue, &prologue)
		prologue.ContentSegments = []uuid.UUID{} // To overwrite, forget previous appends
		marshalPrologue, _ := json.Marshal(prologue)
		SecureAndStore(access.EncryptionKey, access.MACKey, prologueID, marshalPrologue)

		// Edit and Reupload FileContents
		contentsID := prologue.ContentSegments[0]
		decryptedContents, err := VerifyAndDecrypt(access.EncryptionKey, access.MACKey, contentsID)
		if err != nil {
			return
		}
		contents := FileContents{}
		json.Unmarshal(decryptedContents, &contents)
		contents.Data = data
		marshalContents, _ := json.Marshal(contents)
		SecureAndStore(access.EncryptionKey, access.MACKey, contentsID, marshalContents)

	} else {

		// Generate keys for prologue and contents
		encKey, macKey := GenRandEncMacKeys()

		// Create FileContents and store on datastore with random ID
		contentsID := uuid.New()
		contents := FileContents{UUID: contentsID, Data: data}
		marshalContents, _ := json.Marshal(contents)
		SecureAndStore(encKey, macKey, contentsID, marshalContents)

		// Create FilePrologue and store on datastore with random ID
		prologueID := uuid.New()
		prologue := FilePrologue{UUID: prologueID, Owner: userdata.UUID, ContentSegments: []uuid.UUID{contentsID}}
		marshalPrologue, _ := json.Marshal(prologue)
		SecureAndStore(encKey, macKey, prologueID, marshalPrologue)

		// Create a FileAccess
		access = FileAccess{UUID: prologueID, EncryptionKey: encKey, MACKey: macKey}

		// Update user's data with new file and override in datastore
		userdata.Files[filename] = access
		marshalData, _ := json.Marshal(userdata)
		SecureAndStore(encKey, macKey, userdata.UUID, marshalData)
	}
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	// get FileAccess and FilePrologue for filename
	prologue, err := getFilePrologue(userdata, filename)
	if err != nil {
		return err
	}
	access := userdata.Files[filename]

	// Create FileContents and store on datastore with random ID
	contentsID := uuid.New()
	contents := FileContents{UUID: contentsID, Data: data}
	marshalContents, _ := json.Marshal(contents)
	SecureAndStore(access.EncryptionKey, access.MACKey, contentsID, marshalContents)

	// update FilePrologue contentsegments
	prologue.ContentSegments = append(prologue.ContentSegments, contentsID)
	marshalPrologue, _ := json.Marshal(prologue)
	SecureAndStore(access.EncryptionKey, access.MACKey, prologue.UUID, marshalPrologue)

	return nil
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	access, ok := userdata.Files[filename]
	if !ok {
		return nil, errors.New(strings.ToTitle("File does not exist"))
	}
	prologue, err := getFilePrologue(userdata, filename)
	if err != nil {
		return nil, err
	}

	// Loop through all segments and concatenate them
	fullContents := []byte{}
	for _, ID := range prologue.ContentSegments {
		c, err := VerifyAndDecrypt(access.EncryptionKey, access.MACKey, ID)
		if err != nil {
			return nil, err
		}
		var content FileContents
		err = json.Unmarshal(c, &content)
		if err != nil {
			return nil, err
		}
		fullContents = append(fullContents, content.Data...)
	}
	return fullContents, nil
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	return
}
