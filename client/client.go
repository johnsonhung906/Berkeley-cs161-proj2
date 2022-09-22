package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	"strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).

// You can add other attributes here if you want! But note that in order for attributes to
// be included when this struct is serialized to/from JSON, they must be capitalized.
// On the flipside, if you have an attribute that you want to be able to access from
// this struct's methods, but you DON'T want that value to be included in the serialized value
// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
// begins with a lowercase letter).

type User struct {
	Username string
	UserID uuid.UUID
	NewFileNodeDec userlib.PrivateKeyType // private key
	FileNodeEnc []byte // symmetric key for file node (encryption)
	FileNodeVer []byte // symmetric key for file node (verification)

	// for sharing system
	InviteRecDec userlib.PrivateKeyType
	InviteSendSign userlib.PrivateKeyType
}

type FileNodeKeys struct {
	// key for encrypt and sign FileNode
	EncFileKey []byte
	VerFileKey []byte
}

type ShareInvite struct {
	EncNodeKey []byte
	NodeID uuid.UUID
}

// invitation is coping file node and share to others
type FileNode struct {
	FileID uuid.UUID
	EncFileKey []byte
	VerFileKey []byte
	ShareTreeRoot uuid.UUID
}

type File struct {
	RootString string
	Counter int
	NewFileNodeVer []byte // private key
}

type TreeNode struct {
	Childs []uuid.UUID
	Username string
	Filename string
}

func ErrorHandle (err error) () {
	if err != nil {
		panic(err)
	}
	return
}

// NOTE: The following methods have toy (insecure!) implementations.

func UserEncKeyGen(username string, password string) (EncKey []byte) {
	// symmetric key generataion for encryption and decryption a user
	EncKey = userlib.Argon2Key([]byte(password), []byte(username), 16)
	return EncKey
}

func UserVerKeyGen(username string, password string) (VerKey []byte) {
	// symmetric key generataion for verifiaction a user
	VerKey = userlib.Argon2Key([]byte(password), []byte(username + "aaa"), 16)
	return VerKey
}

func SymEncSign(VerKey []byte, EncKey []byte, userBytes []byte) (SignEncUser []byte, err error) {
	EncUser := userlib.SymEnc(EncKey, userlib.RandomBytes(16), userBytes)
	MACUser, err := userlib.HMACEval(VerKey, EncUser)
	if (err != nil) {
		return nil, err
	}
	// userlib.DebugMsg("enc ciphertext: %v", EncUser)
	// userlib.DebugMsg("mac user key: %v", MACUser)
	SignEncUser = append(EncUser, MACUser...)
	return SignEncUser, nil
}

func SymVerDec(VerKey []byte, EncKey []byte, SignEncUser []byte) (VerDecUser []byte, err error) {
	if (len(SignEncUser) < 64) {
		return nil, errors.New(strings.ToTitle("no mac found"))
	}
	MAC := SignEncUser[len(SignEncUser)-64:]
	ciphertext := SignEncUser[:len(SignEncUser)-64]
	// userlib.DebugMsg("enc ciphertext: %v", ciphertext)
	MACUser, err := userlib.HMACEval(VerKey, ciphertext)
	if (err != nil) {
		return nil, err
	}
	// userlib.DebugMsg("mac user key: %v", MACUser)
	if (!userlib.HMACEqual(MACUser, MAC)) {
		return nil, errors.New(strings.ToTitle("MAC"))
	}
	VerDecUser = userlib.SymDec(EncKey, ciphertext)
	return VerDecUser, nil
}

// asymmetric encrypt and asymmetric decrypt
func ASymEncSign(VerKey userlib.PrivateKeyType, EncKey userlib.PublicKeyType, userBytes []byte) (SignEncUser []byte, err error) {
	EncUser, err := userlib.PKEEnc(EncKey, userBytes)
	if (err != nil) {
		return nil, err
	}
	SignUser, err := userlib.DSSign(VerKey, EncUser)
	if (err != nil) {
		return nil, err
	}
	// userlib.DebugMsg("enc ciphertext: %v", EncUser)
	// userlib.DebugMsg("mac user key: %v", MACUser)
	SignEncUser = append(EncUser, SignUser...)
	return SignEncUser, nil
}

func ASymVerDec(VerKey userlib.PublicKeyType, EncKey userlib.PrivateKeyType, SignEncUser []byte) (VerDecUser []byte, err error) {
	if (len(SignEncUser) < 256) {
		return nil, errors.New(strings.ToTitle("no sign found"))
	}
	sign := SignEncUser[len(SignEncUser)-256:]
	ciphertext := SignEncUser[:len(SignEncUser)-256]
	// userlib.DebugMsg("enc ciphertext: %v", ciphertext)
	err = userlib.DSVerify(VerKey, ciphertext, sign)
	// userlib.DebugMsg("mac user key: %v", MACUser)
	if (err != nil) {
		return nil, err
	}
	VerDecUser, err = userlib.PKEDec(EncKey, ciphertext)
	if (err != nil) {
		return nil, err
	}
	return VerDecUser, nil
}

// symmetric encrypt and asymmetric decrypt
func SymEncASymSign(VerKey userlib.PrivateKeyType, EncKey []byte, userBytes []byte) (SignEncUser []byte, err error) {
	EncUser := userlib.SymEnc(EncKey, userlib.RandomBytes(16), userBytes)
	SignUser, err := userlib.DSSign(VerKey, EncUser)
	if (err != nil) {
		return nil, err
	}
	// userlib.DebugMsg("enc ciphertext: %v", EncUser)
	// userlib.DebugMsg("mac user key: %v", MACUser)
	SignEncUser = append(EncUser, SignUser...)
	return SignEncUser, nil
}

func SymDecASymVer(VerKey userlib.PublicKeyType, EncKey []byte, SignEncUser []byte) (VerDecUser []byte, err error) {
	sign := SignEncUser[len(SignEncUser)-256:]
	ciphertext := SignEncUser[:len(SignEncUser)-256]
	// userlib.DebugMsg("enc ciphertext: %v", ciphertext)
	err = userlib.DSVerify(VerKey, ciphertext, sign)
	// userlib.DebugMsg("mac user key: %v", MACUser)
	if (err != nil) {
		return nil, err
	}
	VerDecUser = userlib.SymDec(EncKey, ciphertext)
	return VerDecUser, nil
}

// symmetric encrypt and asymmetric decrypt
func ASymEncSymSign(VerKey []byte, EncKey userlib.PublicKeyType, userBytes []byte) (SignEncUser []byte, err error) {
	EncUser, err := userlib.PKEEnc(EncKey, userBytes)
	if (err != nil) {
		return nil, err
	}
	MACUser, err := userlib.HMACEval(VerKey, EncUser)
	if (err != nil) {
		return nil, err
	}
	// userlib.DebugMsg("enc ciphertext: %v", EncUser)
	// userlib.DebugMsg("mac user key: %v", MACUser)
	SignEncUser = append(EncUser, MACUser...)
	return SignEncUser, nil
}

func ASymDecSymVer(VerKey []byte, EncKey userlib.PrivateKeyType, SignEncUser []byte) (VerDecUser []byte, err error) {
	if (len(SignEncUser) < 64) {
		return nil, errors.New(strings.ToTitle("no mac found"))
	}
	MAC := SignEncUser[len(SignEncUser)-64:]
	ciphertext := SignEncUser[:len(SignEncUser)-64]
	// userlib.DebugMsg("enc ciphertext: %v", ciphertext)
	MACUser, err := userlib.HMACEval(VerKey, ciphertext)
	if (err != nil) {
		return nil, err
	}
	// userlib.DebugMsg("mac user key: %v", MACUser)
	if (!userlib.HMACEqual(MACUser, MAC)) {
		return nil, errors.New(strings.ToTitle("MAC"))
	}
	VerDecUser, err = userlib.PKEDec(EncKey, ciphertext)
	if (err != nil) {
		return nil, err
	}

	return VerDecUser, nil
}


func UserUUIDGen(username string) (id uuid.UUID, err error) {
	// uuid of a user
	id, err = uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if (err != nil) {
		return id, err
	}
	return id, nil
}

// create a file node uuid for context 
func FileNodeUUIDGen(username string, filename string) (id uuid.UUID, err error) {
	id, err = uuid.FromBytes(append(userlib.Hash([]byte(filename))[:8], userlib.Hash([]byte(username))[:8]...))
	if (err != nil) {
		return id, err
	}
	return id, nil
}

func FileNodeUpdateUUIDGen(username string, filename string) (id uuid.UUID, err error) {
	id, err = uuid.FromBytes(append(userlib.Hash([]byte(filename))[:4], userlib.Hash([]byte(username))[:12]...))
	if (err != nil) {
		return id, err
	}
	return id, nil
}

func NewFileNodeID(username string) (key string) {
	return username
}

// func PKInviteSendID(username string) (key string) {
// 	return username + "/invite_send_pk"
// }

func DSInviteSendID(username string) (key string) {
	return username + "/invite_send_ds"
}

func PKInviteRecID(username string) (key string) {
	return username + "/receive_send"
}

// func DSInviteRecID(username string) (key string) {
// 	return username + "/receive_send_ds"
// }

func FileUUIDGen(rootstring string, count int) (id uuid.UUID, err error) {
	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte(rootstring + strconv.Itoa(count)))
	id, err = uuid.FromBytes(hash[:16])
	if (err != nil) {
		return id, err
	}
	return id, nil
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	if (username == "") {
		return nil, errors.New(strings.ToTitle("user name cannot be empty"))
	}
	var userdata User
	id, err := UserUUIDGen(username)
	if err != nil {
		return nil, err
	}
	_, ok := userlib.DatastoreGet(id) 
	if (ok) {
		return nil, errors.New(strings.ToTitle("The client SHOULD assume that each user has a unique username."))
	}
	// userlib.DebugMsg("init user key: %v", id)
	userdata.Username = username
	userdata.UserID = id
	// create keys for filenode 
	userdata.FileNodeEnc = userlib.RandomBytes(16)
	userdata.FileNodeVer = userlib.RandomBytes(16)
	// create a public, private key for the file node key management
	PKEEncKey, PKEDecKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	userdata.NewFileNodeDec = PKEDecKey
	// store public key in keystore
	userlib.KeystoreSet(NewFileNodeID(username), PKEEncKey)
	if err != nil {
		return nil, err
	}
	// create keys for invitation
	PKERecEncKey, PKERecDecKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	userdata.InviteRecDec = PKERecDecKey
	// store public key in keystore
	userlib.KeystoreSet(PKInviteRecID(username), PKERecEncKey)
	if err != nil {
		return nil, err
	}

	DSSendSignKey, DSSendVerKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	userdata.InviteSendSign = DSSendSignKey
	// store public key in keystore
	userlib.KeystoreSet(DSInviteSendID(username), DSSendVerKey)

	EncKey := UserEncKeyGen(username, password)
	VerKey := UserVerKeyGen(username, password)
	// userlib.DebugMsg("EncKey: %v, VerKey: %v", EncKey, VerKey)
	// userlib.DebugMsg("init user: %v", userdata)
	userBytes, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	SignEncUser, err := SymEncSign(VerKey, EncKey, userBytes)
	if err != nil {
		return nil, err
	}
	// userlib.DebugMsg("init user bytes: %v", VerEncUser)
	userlib.DatastoreSet(id, SignEncUser)

	return &userdata, err
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	EncKey := UserEncKeyGen(username, password)
	VerKey := UserVerKeyGen(username, password)
	id, err := UserUUIDGen(username)
	if err != nil {
        return nil, err
    }
	// userlib.DebugMsg("get user key: %v", key)
	SignEncUser, ok := userlib.DatastoreGet(id) 
	if (!ok) {
		return nil, errors.New(strings.ToTitle("user not found"))
	}
	// userlib.DebugMsg("get user bytes: %v", SignEncUser)
	UserBytes, err := SymVerDec(VerKey, EncKey, SignEncUser)
	if err != nil {
        return nil, err
    }
	json.Unmarshal(UserBytes, &userdata)
    if err != nil {
        return nil, err
    }
	// userlib.DebugMsg("get user: %v", userdata)
	
	userdataptr = &userdata

	return userdataptr, nil
}

func UpdateFileNode(filename string, userdata *User) error {
	// check if there exist update node or not
	UpdateFileNodeID, err := FileNodeUpdateUUIDGen(userdata.Username, filename)
	// userlib.DebugMsg("%v %v load file: %v", userdata.Username, filename, FileNodeID)
	if err != nil {
		return err
	}
	newFilodeNodeEnc, ok := userlib.DatastoreGet(UpdateFileNodeID)
	if !ok {
		return errors.New(strings.ToTitle("no exist update node"))
	}

	FileNodeID, err := FileNodeUUIDGen(userdata.Username, filename)
	// userlib.DebugMsg("%v %v load file: %v", userdata.Username, filename, FileNodeID)
	if err != nil {
		return err
	}
	dataJSON, ok := userlib.DatastoreGet(FileNodeID)
	var node FileNode
	var file File
	if !ok {
		return errors.New(strings.ToTitle("file not found"))
	}
	// userlib.DebugMsg("load file node")
	FileNodeBytes, err := SymVerDec(userdata.FileNodeVer, userdata.FileNodeEnc, dataJSON)
	if err != nil {
		// test if key has changed
		return err
	}
	json.Unmarshal(FileNodeBytes, &node)
	SignEncFile, ok := userlib.DatastoreGet(node.FileID)
	if !ok {
		return errors.New(strings.ToTitle("can't get file"))
	}
	// userlib.DebugMsg("load file")
	FileBytes, err := SymVerDec(node.VerFileKey, node.EncFileKey, SignEncFile)
	if err != nil {
		return err
	}
	json.Unmarshal(FileBytes, &file)

	// decrypt updated node and encrypt with user's key
	newFileNode, err := ASymDecSymVer(file.NewFileNodeVer, userdata.NewFileNodeDec, newFilodeNodeEnc)
	if err != nil {
		return err
	}
	var newNode FileNodeKeys
	json.Unmarshal(newFileNode, &newNode)
	
	node.VerFileKey = newNode.VerFileKey
	node.EncFileKey = newNode.EncFileKey

	newFileNodeBytes, err := json.Marshal(node)
	if err != nil {
		return err
	}

	userlib.DebugMsg("new file node :%v", node)
	
	SavedFileNode, err := SymEncSign(userdata.FileNodeVer, userdata.FileNodeEnc, newFileNodeBytes)
	if err != nil {
		return err
	}
	// userlib.DebugMsg("init user bytes: %v", VerEncUser)
	userlib.DatastoreSet(FileNodeID, SavedFileNode)
	userlib.DebugMsg("update file node")


	userlib.DebugMsg("saved file: %v", FileBytes)
	// update the encryption of the file struct
	SavedFile, err := SymEncSign(newNode.VerFileKey, newNode.EncFileKey, FileBytes)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(node.FileID, SavedFile)

	// delete update node
	userlib.DatastoreDelete(UpdateFileNodeID)

	return nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	UpdateFileNode(filename, userdata)
	FileNodeID, err := FileNodeUUIDGen(userdata.Username, filename)
	if err != nil {
        return err
    }
	// check if there is a file already store in that file id
	EncFileNodeData, ok := userlib.DatastoreGet(FileNodeID) 
	var node FileNode
	var file File
	if (ok) {
		// if there is an existing file node, verify and decrypt it
		FileNodeBytes, err := SymVerDec(userdata.FileNodeVer, userdata.FileNodeEnc, EncFileNodeData)
		if err != nil {
			return err
		}
		json.Unmarshal(FileNodeBytes, &node)
		SignEncFile, ok := userlib.DatastoreGet(node.FileID)
		if (!ok) {
			errors.New(strings.ToTitle("can't get file"))
		}
		FileBytes, err := SymVerDec(node.VerFileKey, node.EncFileKey, SignEncFile)
		if err != nil {
			return err
		}
		json.Unmarshal(FileBytes, &file)
	} else {
		// there is no existing file node
		// create a file node which will store keys and uuid for file
		// userlib.DebugMsg("no existing file node")
		node.FileID = uuid.New()
		node.EncFileKey = userlib.RandomBytes(16)
		node.VerFileKey = userlib.RandomBytes(16)
		node.ShareTreeRoot = uuid.New()

		// create a new tree root
		var root TreeNode
		root.Username = userdata.Username
		root.Filename = filename
		TreeBytes, err := json.Marshal(root)
		if err != nil {
			return err
		}
		SignEncTreeNode, err := SymEncSign(node.VerFileKey, node.EncFileKey, TreeBytes)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(node.ShareTreeRoot, SignEncTreeNode)

		// store file node in datastore
		nodeBytes, err := json.Marshal(node)
		if err != nil {
			return err
		}
		SignEncFileNode, err := SymEncSign(userdata.FileNodeVer, userdata.FileNodeEnc, nodeBytes)
		if err != nil {
			return err
		}
		// userlib.DebugMsg("init user bytes: %v", VerEncUser)
		userlib.DatastoreSet(FileNodeID, SignEncFileNode)
		file.RootString = uuid.New().String()
		// create a new signing key for file 
		file.NewFileNodeVer = userlib.RandomBytes(16)
	}
	// find that file and store value to it
	// Also, set count to 1
	file.Counter = 1
	SignEncContent, err := SymEncSign(node.VerFileKey, node.EncFileKey, content)
	if err != nil {
		return err
	}
	// userlib.DebugMsg("init user bytes: %v", VerEncUser)
	FileUUID, err := FileUUIDGen(file.RootString, 0)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(FileUUID, SignEncContent)
	
	fileBytes, err := json.Marshal(file)
	if err != nil {
		return err
	}
	SignEncFile, err := SymEncSign(node.VerFileKey, node.EncFileKey, fileBytes)
	if err != nil {
		return err
	}
	// userlib.DebugMsg("init user bytes: %v", VerEncUser)
	userlib.DatastoreSet(node.FileID, SignEncFile)
	// userlib.DebugMsg("stored file node: %v", node)
	// userlib.DebugMsg("stored file: %v", file)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	err := UpdateFileNode(filename, userdata)
	userlib.DebugMsg("update error: %v", err)
	FileNodeID, err := FileNodeUUIDGen(userdata.Username, filename)
	if err != nil {
		return err
	}
	// check if there is a file already store in that file id
	EncFileNodeData, ok := userlib.DatastoreGet(FileNodeID)
	if (ok) {
		var node FileNode
		var file File
		// loading file
		FileNodeBytes, err := SymVerDec(userdata.FileNodeVer, userdata.FileNodeEnc, EncFileNodeData)
		if err != nil {
			return err
		}
		json.Unmarshal(FileNodeBytes, &node)
		SignEncFile, ok := userlib.DatastoreGet(node.FileID)
		if (!ok) {
			errors.New(strings.ToTitle("can't get file"))
		}
		FileBytes, err := SymVerDec(node.VerFileKey, node.EncFileKey, SignEncFile)
		if err != nil {
			return err
		}
		json.Unmarshal(FileBytes, &file)
		// load and write
		writeID, err := FileUUIDGen(file.RootString, file.Counter)
		if err != nil {
			return err
		}
		file.Counter++
		SignEncContent, err := SymEncSign(node.VerFileKey, node.EncFileKey, content)
		if err != nil {
			return err
		}
		// userlib.DebugMsg("init user bytes: %v", VerEncUser)
		userlib.DatastoreSet(writeID, SignEncContent)

		// store file
		fileBytes, err := json.Marshal(file)
		if err != nil {
			return err
		}
		SignEncFileNew, err := SymEncSign(node.VerFileKey, node.EncFileKey, fileBytes)
		if err != nil {
			return err
		}
		// userlib.DebugMsg("init user bytes: %v", VerEncUser)
		userlib.DatastoreSet(node.FileID, SignEncFileNew)
	} else {
		return errors.New(strings.ToTitle("file not found"))
	}
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	err = UpdateFileNode(filename, userdata)
	userlib.DebugMsg("update error: %v", err)
	FileNodeID, err := FileNodeUUIDGen(userdata.Username, filename)
	// userlib.DebugMsg("%v %v load file: %v", userdata.Username, filename, FileNodeID)
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(FileNodeID)
	var node FileNode
	var file File
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	// userlib.DebugMsg("load file node")
	FileNodeBytes, err := SymVerDec(userdata. FileNodeVer, userdata.FileNodeEnc, dataJSON)
	if err != nil {
		// test if key has changed
		return nil, err
	}
	json.Unmarshal(FileNodeBytes, &node)
	userlib.DebugMsg("file node: %v", node)
	SignEncFile, ok := userlib.DatastoreGet(node.FileID)
	if !ok {
		return nil, errors.New(strings.ToTitle("can't get file"))
	}
	// userlib.DebugMsg("load file")
	FileBytes, err := SymVerDec(node.VerFileKey, node.EncFileKey, SignEncFile)
	if err != nil {
		return nil, err
	}
	userlib.DebugMsg("load file success")
	json.Unmarshal(FileBytes, &file)
	userlib.DebugMsg("file: %v", file)
	userlib.DebugMsg("file key %v %v", node.VerFileKey, node.EncFileKey)
	for cnt := 0; cnt < file.Counter; cnt++ {
		BlockID, err := FileUUIDGen(file.RootString, cnt)
		if err != nil {
			return nil, err
		}
		SignEncContent, dok := userlib.DatastoreGet(BlockID)
		if (!dok) {
			return nil, errors.New(strings.ToTitle("file block not found"))
		}
		// userlib.DebugMsg("load block byte")
		BlockBytes, err := SymVerDec(node.VerFileKey, node.EncFileKey, SignEncContent)
		if err != nil {
			return nil, err
		}
		// userlib.DebugMsg("load block byte success")
		// append blockcontent to content
		content = append(content, BlockBytes...)
	}
	userlib.DebugMsg("finish loading")
	// userlib.DebugMsg("this is file %v", file.RootID)
	// userlib.DebugMsg("this is file %v", content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	inviteKeyPtr uuid.UUID, err error) {
	err = UpdateFileNode(filename, userdata)
	userlib.DebugMsg("update error: %v", err)
	invitationPtr := uuid.New()
	inviteKeyPtr = uuid.New()

	FileNodeID, err := FileNodeUUIDGen(userdata.Username, filename)
	if err != nil {
		return inviteKeyPtr, err
	}
	dataJSON, ok := userlib.DatastoreGet(FileNodeID)
	if ok {
		// userlib.DebugMsg("load file node")
		FileNodeBytes, err := SymVerDec(userdata.FileNodeVer, userdata.FileNodeEnc, dataJSON)
		if err != nil {
			return inviteKeyPtr, err
		}
		// find the node in tree structure and append a new node to it
		var node FileNode
		json.Unmarshal(FileNodeBytes, &node)
		InviteEncKey, ok := userlib.KeystoreGet(PKInviteRecID(recipientUsername))
		if !ok {
			return inviteKeyPtr, errors.New(strings.ToTitle("can't find public key"))
		}
		var invite ShareInvite
		invite.NodeID = invitationPtr
		invite.EncNodeKey = userlib.RandomBytes(16)

		inviteBytes, err := json.Marshal(invite)
		if err != nil {
			return inviteKeyPtr, errors.New(strings.ToTitle("can't marshal"))
		}

		// userlib.DebugMsg("ready to sign")
		SignEncIniviteNode, err := ASymEncSign(userdata.InviteSendSign, InviteEncKey, inviteBytes)
		if err != nil {
			return inviteKeyPtr, err
		}
		// userlib.DebugMsg("finish signing")
		// sign with recipient's public key and encrpt with invitor's
		userlib.DatastoreSet(inviteKeyPtr, SignEncIniviteNode)

		SignEncNode, err := SymEncASymSign(userdata.InviteSendSign, invite.EncNodeKey, FileNodeBytes)
		if err != nil {
			return inviteKeyPtr, err
		}
		userlib.DatastoreSet(invitationPtr, SignEncNode)

	} else {
		return inviteKeyPtr, errors.New(strings.ToTitle("create invite fail: file not found"))
	}
	return inviteKeyPtr, nil
}

func Recur(nodeID uuid.UUID, sender string, VerKey []byte, EncKey []byte) (id uuid.UUID, Find bool) {
	EncTreeNode, ok := userlib.DatastoreGet(nodeID)
	if (!ok) {
		return id, false
	}
	TreeBytes, err := SymVerDec(VerKey, EncKey, EncTreeNode)
	if (err != nil) {
		return id, false
	}
	var node TreeNode
	json.Unmarshal(TreeBytes, &node)
	if (node.Username == sender) {
		return nodeID, true
	} else if (len(node.Childs) == 0) {
		return id, false
	} else {
		for _, childID := range node.Childs {
			nid, find := Recur(childID, sender, VerKey, EncKey)
			if (find) {
				return nid, find
			}
		}
	}
	return id, false
}	

func RecurTree(root uuid.UUID, sender string, recipientUsername string, filename string, VerKey []byte, EncKey []byte) (err error) {
	id, find := Recur(root, sender, VerKey, EncKey)
	if (!find) {
		return errors.New(strings.ToTitle("can't find node"))
	}
	// userlib.DebugMsg("recur find id: %v", id)
	EncTreeNode, ok := userlib.DatastoreGet(id)
	if (!ok) {
		return errors.New(strings.ToTitle("can't find node"))
	}
	TreeBytes, err := SymVerDec(VerKey, EncKey, EncTreeNode)
	var node TreeNode
	json.Unmarshal(TreeBytes, &node)
	newID := uuid.New()
	node.Childs = append(node.Childs, newID)

	// save old tree node
	TreeBytes, err = json.Marshal(node)
	if err != nil {
		return err
	}
	SignEncTreeNode, err := SymEncSign(VerKey, EncKey, TreeBytes)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(id, SignEncTreeNode)

	// save old tree node
	var nodenew TreeNode
	nodenew.Username = recipientUsername
	nodenew.Filename = filename

	TreeBytesNew, err := json.Marshal(nodenew)
	if err != nil {
		return err
	}
	SignEncTreeNodeNew, err := SymEncSign(VerKey, EncKey, TreeBytesNew)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(newID, SignEncTreeNodeNew)
	return 
}


func (userdata *User) AcceptInvitation(senderUsername string, inviteKeyPtr uuid.UUID, filename string) error {
	// if user already have this filename in his directory, then return error
	TestNodeID, err := FileNodeUUIDGen(userdata.Username, filename)
	if err != nil {
		return err
	}
	_, ok := userlib.DatastoreGet(TestNodeID)
	if ok {
		return errors.New(strings.ToTitle("The caller already has a file with the given filename in their personal file namespace."))
	}

	dataJSON, ok := userlib.DatastoreGet(inviteKeyPtr)
	if ok {
		InviteDSKey, ok := userlib.KeystoreGet(DSInviteSendID(senderUsername))
		if !ok {
			return errors.New(strings.ToTitle("can't find public key"))
		}
		// userlib.DebugMsg("decrypt invite node")
		InviteBytes, err := ASymVerDec(InviteDSKey, userdata.InviteRecDec, dataJSON)
		if err != nil {
			return err
		}
		// userlib.DebugMsg("finish decrypt invite node")
		var invite ShareInvite
		json.Unmarshal(InviteBytes, &invite)

		EncFileNode, ok := userlib.DatastoreGet(invite.NodeID)
		// userlib.DebugMsg("decrypt file node")
		FileNodeBytes, err := SymDecASymVer(InviteDSKey, invite.EncNodeKey, EncFileNode)
		if err != nil {
			return err
		}
		// userlib.DebugMsg("stored file bytes: %v", FileNodeBytes)
		var node FileNode
		json.Unmarshal(FileNodeBytes, &node)
		// userlib.DebugMsg("stored file node: %v", node)

		err = RecurTree(node.ShareTreeRoot, senderUsername, userdata.Username, filename, node.VerFileKey, node.EncFileKey)
		if err != nil {
			return err
		}

		// write to user's file storage
		FileUpdateNodeID, err := FileNodeUUIDGen(userdata.Username, filename)
		if err != nil {
			return err
		}
		SignEncFileNode, err := SymEncSign(userdata.FileNodeVer, userdata.FileNodeEnc, FileNodeBytes)
		if err != nil {
			return err
		}
		// userlib.DebugMsg("init user bytes: %v", VerEncUser)
		userlib.DatastoreSet(FileUpdateNodeID, SignEncFileNode)
		// userlib.DebugMsg("stored file node: %v", node)
		// userlib.DebugMsg("stored file: %v", file)
		return nil
	} else {
		return errors.New(strings.ToTitle("file not found"))
	}
	return nil
}

func DeleteTree(nodeByte []byte, id uuid.UUID, oldVerFileKey []byte, oldEncFileKey []byte, newVerFileKey []byte, newEncFileKey []byte, recipientUsername string, NewFileSignKey []byte) (err error) {
	EncTreeNode, ok := userlib.DatastoreGet(id)
	if (!ok) {
		return errors.New(strings.ToTitle("can't find node"))
	}
	TreeBytes, err := SymVerDec(oldVerFileKey, oldEncFileKey, EncTreeNode)
	if (err != nil) {
		return 
	}
	var node TreeNode
	json.Unmarshal(TreeBytes, &node)
	if (node.Username == recipientUsername) {
		return 
	}
	// userlib.DebugMsg("loss access: %v", node.Username)
	// find all its childs
	for _, childID := range node.Childs {
		err = DeleteTree(nodeByte, childID, oldVerFileKey, oldEncFileKey, newVerFileKey, newEncFileKey, recipientUsername, NewFileSignKey)
		if (err != nil) {
			return 
		}
	}

	// update the tree nodes
	newTreeBytes, err := SymEncSign(newVerFileKey, newEncFileKey, TreeBytes)
	if (err != nil) {
		return err
	}
	userlib.DatastoreSet(id, newTreeBytes)

	// update the file node 
	FileUpdateNodeID, err := FileNodeUpdateUUIDGen(node.Username, node.Filename)
	userlib.DebugMsg("create a update file node for %v / %v", node.Username, node.Filename)
	if (err != nil) {
		return err
	}
	// sign with user's public key and sign by file keys
	NewFileEncKey, ok := userlib.KeystoreGet(NewFileNodeID(node.Username))
	if !ok {
		return errors.New(strings.ToTitle("NewFileNode key not found"))
	}

	userlib.DebugMsg("ready to sign node")
	EncNodeBytes, err := ASymEncSymSign(NewFileSignKey, NewFileEncKey, nodeByte)
	if (err != nil) {
		return err
	}
	userlib.DebugMsg("node signed")
	userlib.DatastoreSet(FileUpdateNodeID, EncNodeBytes)

	return
}

func RevokeTree(nodeByte [] byte, oldVerFileKey []byte, oldEncFileKey []byte, recipientUsername string, node FileNode, SignKey []byte) (err error) {
	err = DeleteTree(nodeByte, node.ShareTreeRoot, oldVerFileKey, oldEncFileKey, node.VerFileKey, node.EncFileKey, recipientUsername, SignKey)
	return err
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// this is a wrong but simple implementation
	FileNodeID, err := FileNodeUUIDGen(userdata.Username, filename)
	if err != nil {
		return err
	}
	dataJSON, ok := userlib.DatastoreGet(FileNodeID)
	var node FileNode
	if ok {
		// create new key for new file node and broadcast to all the other user
		FileNodeBytes, err := SymVerDec(userdata.FileNodeVer, userdata.FileNodeEnc, dataJSON)
		if err != nil {
			return err
		}
		json.Unmarshal(FileNodeBytes, &node)
		newEncFileKey := userlib.RandomBytes(16)
		newVerFileKey := userlib.RandomBytes(16)
		oldEncFileKey := node.EncFileKey
		oldVerFileKey := node.VerFileKey
		node.VerFileKey = newVerFileKey
		node.EncFileKey = newEncFileKey
		// Decrypt and re-encrypt the file and file content and tree nodes with new EncKey and new VerKey
		EncFileBytes, ok := userlib.DatastoreGet(node.FileID)
		FileBytes, err := SymVerDec(oldVerFileKey, oldEncFileKey, EncFileBytes)
		var file File
		json.Unmarshal(FileBytes, &file)
		if !ok {
			return errors.New(strings.ToTitle("file not found"))
		}
		userlib.DebugMsg("key enc: %v %v", node.VerFileKey, node.EncFileKey)
		
		for cnt := 0; cnt < file.Counter; cnt++ {
			BlockID, err := FileUUIDGen(file.RootString, cnt)
			if err != nil {
				return err
			}
			SignEncContent, dok := userlib.DatastoreGet(BlockID)
			if (!dok) {
				return errors.New(strings.ToTitle("file block not found"))
			}
			// userlib.DebugMsg("load block byte")
			BlockBytes, err := SymVerDec(oldVerFileKey, oldEncFileKey, SignEncContent)
			if err != nil {
				return err
			}
			newBlockBytes, err := SymEncSign(node.VerFileKey, node.EncFileKey, BlockBytes)
			if err != nil {
				return err
			}
			userlib.DatastoreSet(BlockID, newBlockBytes)
		}
		SignKey := file.NewFileNodeVer
		
		var keynode FileNodeKeys
		keynode.VerFileKey = node.VerFileKey
		keynode.EncFileKey = node.EncFileKey
		userlib.DebugMsg("key node: %v", keynode)
		nodeByte, err := json.Marshal(keynode)
		userlib.DebugMsg("key node bytes: %v", nodeByte)
		// check if there is recipientUsername in tree

		// Save the new file node to the ppl who still have access
		// And also change the key for the tree
		err = RevokeTree(nodeByte, oldVerFileKey, oldEncFileKey, recipientUsername, node, SignKey)
		return err
	} else {
		return errors.New(strings.ToTitle("file node not found"))
	}
	return nil
}