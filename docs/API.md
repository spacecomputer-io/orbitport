# OrbitPort API Spec

The gateway exposes the following end-points:

### Get Random Seed

Delegates the request to the underlying provider to get a random seed.

**Throughput**

TBD

**Request:** `GET /v1/rand_seed`

**Query Parameters:**
- `provider` (string, optional): The provider to use. At the moment only `aptosorbital` is supported and it is the default.

**Response**
- `value` (string): A 32 byte chunk of random data as a hexadecimal string.
- `sig` (string): The signature provided by the satellite.
- `src` (string): The source of the random data.

**Errors**

TBD

**Example**
```json
{
    "value": "a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890",
    "sig": "3046022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890",
    "src": "space/aptos_orbital"
}
```