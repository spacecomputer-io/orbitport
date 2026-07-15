 # Orbitport | Proto

This directory contains the protobuf definitions for the Orbitport project. 
There are 2 types of protobuf definitions in this directory:
- **External Services**: These define the gRPC services that are exposed by the Orbitport gateway with JSON-RPC. 
They specify the methods that can be called by clients and the messages that are used for communication.
- **Internal Plugins**: The internal plugins that are used for interacting with underlying providers/satellites and third-party services (e.g. authentication, account provider) also have their own protobuf definitions. 

