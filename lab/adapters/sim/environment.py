"""Simulated rural world — a coherent smart-farm shared by all sim sensors.

One physical state instead of independent RNGs, so the whole farm tells a
consistent story:
- a diurnal + seasonal weather model drives air temp/humidity and soil.
- irrigation events raise soil moisture and tank drain + flow; between events
  soil dries and plants transpire.
- livestock activity follows a day/night rhythm; animal temp is stable with
  small variation (a fever spike can be scripted).
- rain raises soil moisture and leaf wetness, refills the tank.

The world also exposes ATTACK HOOKS so the sim can inject the exact conditions
the anomaly detector should catch (spoofed values, sensor stuck, drift).
"""

import math
import random

SECONDS_PER_DAY = 86400


class RuralWorld:
    def __init__(self, clock, seed: int = None):
        self._clock = clock
        self._rng = random.Random(seed)
        self._soil_moisture = 45.0        # %VWC
        self._tank_level = 80.0           # %
        self._raining = False
        self._rain_until = 0
        self._irrigating = False
        self._irrigate_until = 0
        self._last_step = None
        # attack hooks
        self._spoof = {}                  # name -> forced value
        self._fever = False

    def _sod(self, ts):
        return ts % SECONDS_PER_DAY

    def _step(self):
        ts = self._clock.now()
        if self._last_step == ts:
            return
        self._last_step = ts

        # rain events
        if ts >= self._rain_until:
            self._raining = False
            if self._rng.random() < 0.0004:
                self._raining = True
                self._rain_until = ts + self._rng.randint(600, 5400)
        # irrigation: kicks in when soil is dry, during daytime
        h = self._sod(ts) / 3600.0
        if not self._irrigating and self._soil_moisture < 30 and 6 < h < 20:
            self._irrigating = True
            self._irrigate_until = ts + self._rng.randint(300, 1200)
        if ts >= self._irrigate_until:
            self._irrigating = False

        # soil moisture dynamics
        if self._raining:
            self._soil_moisture += 0.15
        elif self._irrigating:
            self._soil_moisture += 0.25
        else:
            self._soil_moisture -= 0.02      # drying / transpiration
        self._soil_moisture = max(5.0, min(100.0, self._soil_moisture))

        # tank: drains while irrigating, refills a bit when raining
        if self._irrigating:
            self._tank_level -= 0.05
        if self._raining:
            self._tank_level += 0.02
        self._tank_level = max(0.0, min(100.0, self._tank_level))

    # -- crops ---------------------------------------------------------------
    def air_temp(self):
        self._step()
        s = self._sod(self._clock.now())
        phase = 2 * math.pi * (s - 5 * 3600) / SECONDS_PER_DAY
        base = 14.0 - math.cos(phase) * 8.0
        if self._raining:
            base -= 2.0
        return self._spoofed("air_temp", base + self._rng.gauss(0, 0.2))

    def air_humidity(self):
        self._step()
        base = 88.0 - (self.air_temp() - 14.0) * 2.2
        if self._raining:
            base = max(base, 95.0)
        return self._spoofed("air_humidity", min(100.0, max(20.0, base + self._rng.gauss(0, 1.5))))

    def soil_moisture(self):
        self._step()
        return self._spoofed("soil_moisture", self._soil_moisture + self._rng.gauss(0, 0.3))

    def soil_temp(self):
        self._step()
        return self._spoofed("soil_temp", self.air_temp() - 3.0 + self._rng.gauss(0, 0.2))

    def leaf_wetness(self):
        self._step()
        base = 70.0 if self._raining else max(0.0, self.air_humidity() - 60.0)
        return self._spoofed("leaf_wetness", min(100.0, base + self._rng.gauss(0, 2.0)))

    # -- water ---------------------------------------------------------------
    def tank_level(self):
        self._step()
        return self._spoofed("tank_level", self._tank_level + self._rng.gauss(0, 0.2))

    def flow_rate(self):
        self._step()
        base = self._rng.uniform(8, 14) if self._irrigating else 0.0
        return self._spoofed("flow_rate", max(0.0, base + self._rng.gauss(0, 0.3)))

    def pump_on(self):
        self._step()
        return 1.0 if self._irrigating else 0.0

    def water_ph(self):
        self._step()
        return self._spoofed("water_ph", 7.0 + self._rng.gauss(0, 0.2))

    # -- livestock -----------------------------------------------------------
    def animal_temp(self):
        self._step()
        base = 38.6 + (1.5 if self._fever else 0.0)
        return self._spoofed("animal_temp", base + self._rng.gauss(0, 0.1))

    def animal_activity(self):
        self._step()
        s = self._sod(self._clock.now())
        h = s / 3600.0
        day = math.exp(-((h - 13) ** 2) / 20.0)
        base = 70.0 * day + 5.0
        return self._spoofed("animal_activity", max(0.0, min(100.0, base + self._rng.gauss(0, 4))))

    def is_raining(self):
        return self._raining

    # -- attack hooks --------------------------------------------------------
    def spoof(self, name: str, value: float):
        """Force a sensor to report an (often impossible) value — simulates a
        compromised/spoofed node. Set to None to clear."""
        if value is None:
            self._spoof.pop(name, None)
        else:
            self._spoof[name] = value

    def set_fever(self, on: bool):
        self._fever = on

    def _spoofed(self, name, real):
        return self._spoof.get(name, real)

    def force_rain(self, duration_s=3600):
        self._raining = True
        self._rain_until = self._clock.now() + duration_s
