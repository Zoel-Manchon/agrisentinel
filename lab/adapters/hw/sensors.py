"""Hardware adapters — SKELETONS, ready to fill when sensors arrive.

Same name/domain + measurement names as the sim adapters, so the swap in
runner/run_sim.py is mechanical. Target: ESP32 (MicroPython). Wiring and
driver plan in WIRING.md.

The security layer (signing) is IDENTICAL on hardware — the node still signs
every frame with HMAC before transmitting. Only the sensor reads change.
"""

from lab.domain.model import Measurement  # noqa: F401 — used when implemented
from lab.domain.ports import SensorError, SensorPort


class HwSoilProbe(SensorPort):
    """Capacitive soil moisture (analog) + DS18B20 soil temp (1-Wire)."""

    name = "soil_probe"
    domain = "crops"

    def __init__(self, adc, onewire_pin=None):
        self._adc = adc
        self._onewire = onewire_pin

    def read(self):
        raise SensorError(self.name, "hardware adapter not implemented yet")
        # TODO(hw): read capacitive ADC -> %VWC (calibrate dry/wet);
        #           read DS18B20 -> soil_temp.


class HwCanopy(SensorPort):
    """BME280 (air temp/humidity/pressure, I2C) + leaf-wetness resistive grid."""

    name = "canopy"
    domain = "crops"

    def __init__(self, i2c, leaf_adc=None):
        self._i2c = i2c
        self._leaf = leaf_adc

    def read(self):
        raise SensorError(self.name, "hardware adapter not implemented yet")


class HwWaterTank(SensorPort):
    """Ultrasonic level (HC-SR04) + flow (YF-S201 pulse) + analog pH probe."""

    name = "water_tank"
    domain = "water"

    def __init__(self, trig_pin=None, echo_pin=None, flow_pin=None, ph_adc=None):
        self._trig = trig_pin
        self._echo = echo_pin
        self._flow = flow_pin
        self._ph = ph_adc

    def read(self):
        raise SensorError(self.name, "hardware adapter not implemented yet")


class HwLivestockCollar(SensorPort):
    """Body temp (MLX90614 IR, I2C) + activity (MPU6050 accel, I2C)."""

    name = "collar"
    domain = "livestock"

    def __init__(self, i2c):
        self._i2c = i2c

    def read(self):
        raise SensorError(self.name, "hardware adapter not implemented yet")
