# Test Setup

NOTE: Implemented services in the odx are not fully tested yet with the CDA,
and for some there are open issues to make them work.

## Test using docker compose

### Prerequisites
- Docker and Docker Compose installed
- ODX converter built (optional, for PDX to MDD conversion)

### Setup

1. **Build and Start testcontainer**

   ```sh
   # Build and start all services
   docker compose build
   docker compose up -d
   ```

2. **Check service status:**
   ```sh
   docker compose ps
   docker compose logs -f
   ```

3. **Access the services:**
   - ECU Simulator Control API: http://localhost:8181
   - CDA SOVD API: http://localhost:20002

### Managing Services

```sh
# Stop all services
docker compose down

# Restart services
docker compose restart

# View logs
docker compose logs -f cda
docker compose logs -f ecu-sim

# Rebuild after code changes
docker compose build cda
docker compose up -d cda
```

---

## Examples

```sh
export ACCESS_TOKEN=$(curl -s -X POST -H "Content-Type: application/json" "http://localhost:20002/vehicle/v15/authorize" --data '{"client_id":"test", "client_secret":"secret"}' | jq -r .access_token)

# retrieve standardized resource collection for ECU (+ variant)
curl -s -X GET -H "Authorization: Bearer $ACCESS_TOKEN" "http://localhost:20002/vehicle/v15/components/FLXC1000" | jq .

# acquire component lock
curl -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" -H "Content-Type: application/json" "http://localhost:20002/vehicle/v15/components/FLXC1000/locks" --data '{"lock_expiration": 100000}'

# switch into extended session
curl -s -X PUT -H "Authorization: Bearer $ACCESS_TOKEN" -H "Content-Type: application/json" "http://localhost:20002/vehicle/v15/components/FLXC1000/modes/session" --data '{"value": "extended"}'

# switch sim to boot variant
curl -s -X PUT -H "Content-Type: application/json" "http://localhost:8181/FLXC1000/state" --data '{"variant": "BOOT"}'

# force variant detection
curl -s -X PUT -H "Authorization: Bearer $ACCESS_TOKEN" -H "Content-Type: application/json" "http://localhost:20002/vehicle/v15/components/FLXC1000"

# security access status
curl -s -X GET -H "Authorization: Bearer $ACCESS_TOKEN" "http://localhost:20002/vehicle/v15/components/FLXC1000/modes/security" | jq .

# request seed (security access)
curl -s -X PUT -H "Content-Type: application/json" -H "Authorization: Bearer $ACCESS_TOKEN" "http://localhost:20002/vehicle/v15/components/FLXC1000/modes/security" --data '{"value": "Level_5_RequestSeed"}' | jq .

# send key (security access) -- doesn't work yet
curl -s -X PUT -H "Content-Type: application/json" -H "Authorization: Bearer $ACCESS_TOKEN" "http://localhost:20002/vehicle/v15/components/FLXC1000/modes/security" --data '{"value": "Level_5", "Key": { "Security": "0x12 0x34 0x56" } }' | jq .

```

## Managing MDD files

The repository contains MDDs file which have been generated via `odxtools` and the python scripts located in `testcontainer/odx/`.
To update them manually run the following commands. This require the odxconverter as described in the repository readme.
This step is only necessary when changes to the ECU database have been made.
For normal operation / testing this is not needed.

```
# Generate ODX files
cd testcontainer/odx
./generate_docker.sh
cd ..

# Convert PDX to MDD (if you have the converter)
cd odx
java -jar <path-to-odx-converter>/converter/build/libs/converter-all.jar FLXC1000.pdx
cd ..
```
