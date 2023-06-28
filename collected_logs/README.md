# Log data

Generally, MMTLS requests are associated with a numeric identifier, the "request type ID". Each request type ID corresponds to an internal API path, such as request type ID 763 and `/cgi-bin/micromsg-bin/secautoauth`. Many other qualities of the MMTLS network request are related to the request type ID. For instance, the type of data each network request contains, whether it uses Protobuf serialization, and sometimes what type of encryption is expected, can be determined by the "request type ID". Generally, the request type ID likely defines which back-end API service WeChat expects to handle that particular network request.

In `request_types.csv`, we provide a mapping between the request type ID and the internal API paths. This list is not at all comprehensive, and we will add to the list as we identify more internal API paths through both static and dynamic analysis of the application.

In our log files, we associate each outgoing request with the internal API path it is intended for. Our analysis script uses the `request_types.csv` to identify the more descriptive internal API path from the request type ID.
