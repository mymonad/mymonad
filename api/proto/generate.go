//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative monad.proto
//go:generate protoc --go_out=. --go_opt=paths=source_relative handshake.proto
//go:generate protoc --go_out=. --go_opt=paths=source_relative discovery.proto
//go:generate protoc --go_out=. --go_opt=paths=source_relative chat.proto

package proto
