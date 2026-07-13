"""Simulated sensors for the three rural domains + power + nonce source.

Each sensor declares its `domain` so the node knows which frame domain to
stamp. Same names the hardware adapters will use, so sim->hw is mechanical.
"""

import os
import random

from lab.domain.model import (
    UNIT_BOOL,
    UNIT_CELSIUS,
    UNIT_LPM,
    UNIT_PERCENT,
    UNIT_PERCENT_VWC,
    UNIT_PH,
    Measurement,
)
from lab.domain.ports import PowerMonitorPort, SensorError, SensorPort


# ------------------------------------------------------------------ crops ---
class SimSoilProbe(SensorPort):
    name = "soil_probe"
    domain = "crops"

    def __init__(self, world, fail_rate=0.0, seed=None):
        self._world = world
        self._fail_rate = fail_rate
        self._rng = random.Random(seed)

    def read(self):
        if self._rng.random() < self._fail_rate:
            raise SensorError(self.name, "simulated bus fault")
        return [
            Measurement("soil_moisture", self._world.soil_moisture(), UNIT_PERCENT_VWC),
            Measurement("soil_temp", self._world.soil_temp(), UNIT_CELSIUS),
        ]


class SimCanopy(SensorPort):
    name = "canopy"
    domain = "crops"

    def __init__(self, world, fail_rate=0.0, seed=None):
        self._world = world
        self._fail_rate = fail_rate
        self._rng = random.Random(seed)

    def read(self):
        if self._rng.random() < self._fail_rate:
            raise SensorError(self.name, "simulated bus fault")
        return [
            Measurement("air_temp", self._world.air_temp(), UNIT_CELSIUS),
            Measurement("air_humidity", self._world.air_humidity(), UNIT_PERCENT),
            Measurement("leaf_wetness", self._world.leaf_wetness(), UNIT_PERCENT),
        ]


# ------------------------------------------------------------------ water ---
class SimWaterTank(SensorPort):
    name = "water_tank"
    domain = "water"

    def __init__(self, world, fail_rate=0.0, seed=None):
        self._world = world
        self._fail_rate = fail_rate
        self._rng = random.Random(seed)

    def read(self):
        if self._rng.random() < self._fail_rate:
            raise SensorError(self.name, "simulated float fault")
        return [
            Measurement("tank_level", self._world.tank_level(), UNIT_PERCENT),
            Measurement("flow_rate", self._world.flow_rate(), UNIT_LPM),
            Measurement("pump_state", self._world.pump_on(), UNIT_BOOL),
            Measurement("water_ph", self._world.water_ph(), UNIT_PH),
        ]


# -------------------------------------------------------------- livestock ---
class SimLivestockCollar(SensorPort):
    name = "collar"
    domain = "livestock"

    def __init__(self, world, fail_rate=0.0, seed=None):
        self._world = world
        self._fail_rate = fail_rate
        self._rng = random.Random(seed)

    def read(self):
        if self._rng.random() < self._fail_rate:
            raise SensorError(self.name, "simulated collar fault")
        return [
            Measurement("animal_temp", self._world.animal_temp(), UNIT_CELSIUS),
            Measurement("animal_activity", self._world.animal_activity(), UNIT_PERCENT),
        ]


# ------------------------------------------------------------------ power ---
class SimPowerMonitor(PowerMonitorPort):
    def __init__(self, world, start_voltage=3.9):
        self._world = world
        self._v = start_voltage

    def battery_voltage(self):
        # slow drift; solar-ish nodes stay healthy
        self._v += random.uniform(-0.003, 0.002)
        self._v = max(3.3, min(4.2, self._v))
        return round(self._v, 3)


# ------------------------------------------------------------ nonce source ---
def make_nonce_source():
    """Return a callable that yields a fresh hex nonce per frame."""
    def _n():
        return os.urandom(6).hex()
    return _n


# test doubles
class StaticSensor(SensorPort):
    def __init__(self, name, domain, measurements):
        self.name = name
        self.domain = domain
        self._m = measurements

    def read(self):
        return list(self._m)
