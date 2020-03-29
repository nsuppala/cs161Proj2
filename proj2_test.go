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
	"github.com/google/uuid"
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
- someone who is not the owner is trying to revoke
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
	if (reflect.DeepEqual(u1.SignKey, userlib.DSSignKey{})) ||
		(reflect.DeepEqual(u1.PKEDecKey, userlib.PKEDecKey{})) ||
		(u1.Files == nil) || (u1.UUID == uuid.UUID{}) ||
		(len(u1.EncryptionKey) == 0) ||
		(len(u1.MACKey) == 0) {
		t.Error("Failed to initialize all user fields", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	//t.Log("Got user", u1)
	// If you want to comment the line above,
	// write _ = u1 here to make the compiler happy
	// You probably want many more tests here.
	u4, err := InitUser("bob", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	_ = u4
	u2, err := InitUser("alice", "foobar")
	if err == nil {
		t.Error("Cannot initialize two users with same name")
		return
	}
	_ = u2
	u3, err := InitUser("", "foobar")
	if err == nil {
		t.Error("Empty string used as username")
		return
	}
	_ = u3
}

func TestGetUser(t *testing.T) {
	clear()

	u1, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	_ = u1
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
	_, err = GetUser("alice", "foobar")
	if err == nil {
		t.Error("Did not detect incorrect password")
		return
	}
	_, err = GetUser("bob", "foobar")
	if err == nil {
		t.Error("Did not detect user does not exist")
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

	_ = u.AppendFile("file1", []byte("This is also a test"))
	f2, _ := u.LoadFile("file1")
	_ = f2

	if reflect.DeepEqual(f2, v2) {
		t.Error("File did not append")
		return
	}
	// Test empty file contents
	v = []byte("")
	u.StoreFile("file2", v)
	v3, err3 := u.LoadFile("file2")
	if err3 != nil {
		t.Error("Failed to upload empty file", err3)
		return
	}
	if !reflect.DeepEqual(v, v3) {
		t.Error("Downloaded file is not the same", v, v3)
		return
	}
	// Append empty contents
	_ = u.AppendFile("file1", v)
	f3, _ := u.LoadFile("file1")
	if !reflect.DeepEqual(f2, f3) {
		t.Error("File did not append")
		return
	}
}

// test file with empty string as filename
func TestEmptyFileName(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("", v)
	_, err3 := u.LoadFile("")
	if err3 != nil {
		t.Error("Failed to upload and download", err3)
		return
	}

	v2, err2 := u.LoadFile("")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestTwoFilesSameName(t *testing.T) {
	clear()
	u, _ := InitUser("alice", "fubar")
	u2, _ := InitUser("bob", "foobar")

	v := []byte("This is a test")
	u.StoreFile("file", v)

	v = []byte("This is a different test")
	u2.StoreFile("file", v)

	v1, _ := u.LoadFile("file")
	v2, _ := u2.LoadFile("file")
	if reflect.DeepEqual(v1, v2) {
		t.Error("Files are the same when they should differ despite same filename")
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
	u, _ := InitUser("alice", "fubar")
	u2, _ := InitUser("bob", "foobar")

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var magic_string string

	v, err := u.LoadFile("file1")
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
	// Should error when sharing a file you don't have
	magic_string, err = u.ShareFile("file3", "bob")
	if err == nil {
		t.Error("Should error when sharing a file that does not exist")
		return
	}
	// Cannot share with user that doesn't exist
	magic_string, err = u.ShareFile("file3", "malice")
	if err == nil {
		t.Error("Cannot share with user that doesn't exist")
		return
	}
}

func TestMultiLevelSharing(t *testing.T) {
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

	//u3, _ := InitUser("eve", "barfoo")
	u4, _ := InitUser("charlie", "bar")

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	/* Single level sharing */
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

	/* Multilevel sharing */
	// bob shares file with charlie
	magic_string, err = u2.ShareFile("file2", "charlie")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u4.ReceiveFile("file4", "bob", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v4, err := u4.LoadFile("file4")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v2, v4)
		return
	}
}

func TestRevokeFile(t *testing.T) {
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

	// revoke file from eve
	_ = u.RevokeFile("file1", "eve")

	// eve shouldn't be able to append
	err := u3.AppendFile("file3", []byte("This is also a file"))
	if err == nil {
		t.Error("Eve was able to append after revoke")
		return
	}

	// bob should still be able to append
	err = u3.AppendFile("file2", []byte("This is also a file"))
	if err != nil {
		t.Error("Bob wasn't able to append after eve was revoke")
		return
	}
}

func TestRevokeNotAsOwner(t *testing.T) {
	clear()
	u, _ := InitUser("alice", "fubar")
	u2, _ := InitUser("bob", "foobar")

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

	// should error if bob tries to revoke bc he is not owner
	err := u2.RevokeFile("file2", "alice")
	if err == nil {
		t.Error("Should error because bob is not the owner")
	}
}

func TestShareAfterRevoke(t *testing.T) {
	clear()
	u, _ := InitUser("alice", "fubar")
	u3, _ := InitUser("eve", "barfoo")

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	// share with eve
	magic_string, _ := u.ShareFile("file1", "eve")
	_ = u3.ReceiveFile("file3", "alice", magic_string)

	// revoke file from eve
	_ = u.RevokeFile("file1", "eve")

	// eve shouldn't be able to share the file
	_, err := u3.ShareFile("file1", "charlie")
	if err == nil {
		t.Log("Eve shouldn't be able to share the file after it is revoked")
	}
}

func TestStoreAfterRevoke(t *testing.T) {
	clear()
	u, _ := InitUser("alice", "fubar")
	u3, _ := InitUser("eve", "barfoo")

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	// share with eve
	magic_string, _ := u.ShareFile("file1", "eve")
	_ = u3.ReceiveFile("file3", "alice", magic_string)

	// revoke file from eve
	_ = u.RevokeFile("file1", "eve")

	// eve shouldn't be able to store file and have it change in datastore
	/* I'm not sure how we should handle this? bc should they still be able to
	store to their file and just not have it change in the datastore? */
	f := []byte("This is a new file")
	u3.StoreFile("file3", f)
	v1, _ := u.LoadFile("file1")
	v3, _ := u3.LoadFile("file3")
	if reflect.DeepEqual(v1, v3) {
		t.Error("Eve shouldn't be able to change file after revoke")
	}
}

func TestSeeChangesAfterRevoke(t *testing.T) {
	clear()
	u, _ := InitUser("alice", "fubar")
	u3, _ := InitUser("eve", "barfoo")

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	// share with eve
	magic_string, _ := u.ShareFile("file1", "eve")
	_ = u3.ReceiveFile("file3", "alice", magic_string)
	v3, _ := u3.LoadFile("file3")

	// revoke file from eve
	_ = u.RevokeFile("file1", "eve")

	// if alice changes file eve shouldn't be able to see changes
	f := []byte("This is a new file")
	u3.StoreFile("file3", v)
	v3, _ = u3.LoadFile("file3")
	u.StoreFile("file1", f)
	v3, _ = u3.LoadFile("file3")
	v1, _ := u.LoadFile("file1")
	if reflect.DeepEqual(v1, v3) {
		t.Error("Eve shouldn't be able to see file changes after revoke")
	}
}

func TestRevokeAfterRevoke(t *testing.T) {
	clear()
	u, _ := InitUser("alice", "fubar")
	u3, _ := InitUser("eve", "barfoo")

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	// share with eve
	magic_string, _ := u.ShareFile("file1", "eve")
	_ = u3.ReceiveFile("file3", "alice", magic_string)

	// revoke file from eve
	_ = u.RevokeFile("file1", "eve")

	// should error if we try to revoke a file after already revoking
	err := u.RevokeFile("file1", "eve")
	if err == nil {
		t.Error("Should error because file is no longer shared with Eve")
	}
}

/* Multi level sharing and revoking */
func TestMultiLevelRevoke(t *testing.T) {
	clear()
	u, _ := InitUser("alice", "fubar")
	u2, _ := InitUser("bob", "foobar")
	u4, _ := InitUser("charlie", "bar")

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

	// bob shares file with charlie
	magic_string, err := u2.ShareFile("file2", "charlie")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u4.ReceiveFile("file4", "bob", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	// alice revokes bob's access which should also revoke charlie's access
	err = u.RevokeFile("file1", "bob")

	// neither bob nor charlie should be able to append
	v4 := u2.AppendFile("file2", []byte("This is also a file"))
	v5, _ := u.LoadFile("file1")

	if reflect.DeepEqual(v4, v5) {
		t.Error("Eve was able to append after revoke")
		return
	}

	v4 = u4.AppendFile("file4", []byte("This is also a file"))
	v5, _ = u.LoadFile("file1")

	if reflect.DeepEqual(v4, v5) {
		t.Error("Eve was able to append after revoke")
		return
	}
}
