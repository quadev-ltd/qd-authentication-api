package binary_creation

import (
	"encoding/base64"
	"io/ioutil"
	"log"
	"qd_authentication_api/internal/pb"

	"google.golang.org/protobuf/proto"
)

func main() {
	userPb := &pb.RegisterRequest{
		Email:    "gusfran17@gmail.com",
		Password: "password",
		// FirstName: "Test",
		// LastName:  "User",
		// DateOfBirth: &timestamppb.Timestamp{
		// 	Seconds: 1234567890,
		// 	Nanos:   123456789,
		// },
	}
	var resolvedUserPb pb.RegisterRequest

	data, error := proto.Marshal(userPb)
	if error != nil {
		log.Fatal("Marshaling error: ", error)
	}

	// Write the binary string to a file
	if err := ioutil.WriteFile("test.bin", data, 0644); err != nil {
		log.Fatalln("Failed to write message:", err)
	}

	log.Println("Data bytes:")
	log.Println(data)

	base64Data := base64.StdEncoding.EncodeToString(data)
	log.Println("Data base 64 string encoded:")
	log.Println(base64Data)

	decodedData, error := base64.StdEncoding.DecodeString("Cg50ZXN0QGVtYWlsLmNvbRIIcGFzc3dvcmQaBFRlc3QiBFVzZXIqCwjShdjMBBCVmu86")
	log.Println("Data base 64 string decoded to bytes:")
	log.Println(decodedData)

	error = proto.Unmarshal(decodedData, &resolvedUserPb)
	if error != nil {
		log.Fatal("Unmarshaling error: ", error)
	}
	log.Println("Data unmarshaled: ")
	log.Println(&resolvedUserPb)
}
