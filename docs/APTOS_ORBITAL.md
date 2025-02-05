# stargate / Aptos Orbital

This document contains information on the integration with `Aptos Orbital` services.

## Aptos Orbital API

The gateway is using the following end-points from `Aptos Orbital API` (`api.aptosorbital.com`):

### Get True Random Seed

Returns a true random seed harvested from hardware on cEDGE and Crypto2 satellites. The satellite also provides a signature to ensure the seed is authentic.

**Throughput**

The end-point can provide up to 1500 32-byte chunks of random data daily, which is a chunk every 1 minute.
The rate should be slower than 1 request / 5 mins to ensure enough entropy.

**Request:**
`GET /services/v1/trng_seed`

**Query Parameters:**
- `no_sig` (int, optional): A boolean int (0 or 1) that determines if a signature from the satellite should be included with the response. Default is 0.
- `num_chunk` (int, optional): Number of chunks, default is 1

**Response**
- `chunk` (string): A 32 byte chunk of random data as a hexadecimal string.
- `signature` (string): The signature provided by the satellite.

**Errors**
- `400` (Bad Request): If `num_bytes` is not a positive integer or exceeds the remaining daily limit.

**Example**
```
GET /services/v1/trng_seed?no_sig=0&num_chunk=1
```    

```json
[{
    "chunk": "a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890",
    "signature": "3046022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890"
}]
```
