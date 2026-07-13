# Hardware plan — agrisentinel

Three field nodes (one per domain), each an ESP32 that signs every frame with
HMAC before transmitting. The security layer is identical to the sim — only
the sensor reads change.

## Node: crop-01 (crops)

| Peripheral | Bus | Pins (ESP32) | Reads |
|-----------|-----|--------------|-------|
| Capacitive soil moisture | ADC | 34 | soil_moisture (%VWC) |
| DS18B20 | 1-Wire | 4 | soil_temp |
| BME280 | I2C | SDA=21, SCL=22, 0x76 | air_temp, air_humidity |
| Leaf-wetness grid | ADC | 35 | leaf_wetness |

## Node: water-01 (water)

| Peripheral | Bus | Pins | Reads |
|-----------|-----|------|-------|
| HC-SR04 ultrasonic | GPIO | TRIG=5, ECHO=18 | tank_level (from distance) |
| YF-S201 flow | GPIO (pulse) | 19 | flow_rate (L/min) |
| Analog pH probe | ADC | 33 | water_ph |
| Relay (pump) | GPIO | 23 | pump_state |

## Node: herd-01 (livestock)

| Peripheral | Bus | Pins | Reads |
|-----------|-----|------|-------|
| MLX90614 IR temp | I2C | SDA=21, SCL=22, 0x5A | animal_temp |
| MPU6050 accel | I2C | SDA=21, SCL=22, 0x68 | animal_activity (from motion) |

## Security on hardware

- Each node stores its HMAC key in NVS / secure storage (provisioned once).
- The signer (`HmacSigner`) is unchanged; the node signs → transmits.
- The gateway (a Raspberry Pi or a spare ESP32 + broker) runs `HmacVerifier`
  + `AnomalyDetector` exactly as in the sim.
- Roadmap: rotate to per-node keys, then to mTLS on the MQTT link (see README).

## Porting note

`lab/domain` and `lab/application` are MicroPython-safe (no
typing/dataclasses/abc/enum, and hmac/hashlib live in the adapter). Copy them
verbatim; only the adapters and composition root differ.
