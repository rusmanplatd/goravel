package routes

import (
	"github.com/goravel/framework/facades"
)

func Grpc() {
	// gRPC services will be registered here when they are implemented
	// For now, this provides a proper foundation for gRPC service registration

	// Example of how to register a gRPC service when implemented:
	// facades.Grpc().Server().RegisterService(&pb.YourService_ServiceDesc, &controllers.YourServiceController{})

	facades.Log().Info("gRPC routes initialized - ready for service registration")
}
