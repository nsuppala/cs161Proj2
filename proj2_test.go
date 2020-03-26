package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	_ "github.com/google/uuid"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

/* Types of tests we need to write:
		- empty string filenames
		- share file, another user appends, original owner loads with changes
		- share file, revoke, old user with access tries to append and it shouldn't change original file
		- trying to revoke a file from someone who doesn't have access
*/

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u1, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	//t.Log("Got user", u1)
	// If you want to comment the line above,
	// write _ = u1 here to make the compiler happy
	_ = u1
	// You probably want many more tests here.

	u2, err1 := GetUser("alice", "fubar")
	if err1 != nil {
		t.Error("Failed to get user", err1)
		return
	}
	//t.Log("Got user", u2)
	_ = u2
	if !reflect.DeepEqual(u1, u2) {
		t.Error("Got incorrect user")
		return
	}
}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}

	u.AppendFile("file1", []byte("This is also a test"))
	f2, _ := u.LoadFile("file1")
	_ = f2

	if reflect.DeepEqual(f2, v2) {
		t.Error("File did not append")
		return
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a nonexistent file", err2)
		return
	}
}

func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
}

func TestRevokeFile( t *testing.T) {
	clear()
	u, _ := InitUser("alice", "fubar")
	u2, _ := InitUser("bob", "foobar")
	u3, _ := InitUser("eve", "barfoo")

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var magic_string string

	// share with bob
	v, _ = u.LoadFile("file1")
	magic_string, _ = u.ShareFile("file1", "bob")
	_ = u2.ReceiveFile("file2", "alice", magic_string)
	v2, _ = u2.LoadFile("file2")
	_ = v2

	// share with eve
	magic_string2, _ := u.ShareFile("file1", "eve")
	_ = u3.ReceiveFile("file3", "alice", magic_string2)
	v3, _ := u3.LoadFile("file3")
	_ = v3

	// revoke file from eve
	_ = u.RevokeFile("file3", "eve")

	// eve shouldn't be able to append
	v4 := u3.AppendFile("file3", []byte("This is also a file"))
	v5, _ := u.LoadFile("file1")

	if reflect.DeepEqual(v4, v5) {
		t.Error("Eve was able to append after revoke")
		return
	}

}
