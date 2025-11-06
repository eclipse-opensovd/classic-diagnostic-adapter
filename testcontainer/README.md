# Test Setup

NOTE: Implemented services in the odx are not fully tested yet with the CDA,
and for some there are open issues to make them work.

## Quick Start with Docker Compose (Recommended)

### Prerequisites
- Docker and Docker Compose installed
- ODX converter built (optional, for PDX to MDD conversion)

### Setup

1. **Generate ODX files and prepare environment:**

   ```sh
   # Generate ODX files
   cd testcontainer/odx
   ./generate_docker.sh
   cd ..
   
   # Build ECU simulator
   cd ecu-sim
   ./gradlew build shadowJar
   cd ..
   
   # Convert PDX to MDD (if you have the converter)
   cd odx
   java -jar <path-to-odx-converter>/converter/build/libs/converter-all.jar FLXC1000.pdx
   cd ..
   
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

## Manual Setup (Alternative)

### Generate odx file(s)

In the directory `testcontainer/odx`, run:

```sh
./generate_docker.sh
```

This should generate the PDX-files:

- FLXDC1000.pdx

### Build & run converter on pdx files

Build the converter with `./gradlew shadowJar` in the odx-converter directory.

Go back to the directory with the `pdx`-files, and execute:
```sh
java -jar <path-to-odx-converter>/converter/build/libs/converter-all.jar FLXC1000.pdx
```

You should now have a `FLXC1000.mdd` and `FLXC1000.mdd.log` in the same directory.

### Build & run the simulation

Goto `testcontainer/ecu-sim/docker`.

Build:
```sh
./build_docker.sh
```

Run:
```sh
./run_docker.sh
```
Needs privileged access, so it can add more ip addresses to the network interface for multiple gateways.

### Build & run the CDA

In the CDA main directory:
```sh
cargo build --release
```

In the `target/release` folder:
```sh
./opensovd-cda -o true -d ../../testcontainer/odx -t 172.17.0.1
```

You might need to change the IP to your docker interface used by the sim.

Currently you need to start the SIM first, haven't analyzed further.

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