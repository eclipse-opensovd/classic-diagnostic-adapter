# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0

from odxtools.diaglayers.diaglayerraw import DiagLayerRaw
from odxtools.nameditemlist import NamedItemList
from odxtools.physicaldimension import PhysicalDimension
from odxtools.unit import Unit
from odxtools.unitspec import UnitSpec

from helper import derived_id, ref


def add_common_units(dlr: DiagLayerRaw):
    pdim_raw = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.Raw"),
        short_name="Raw",
    )
    pdim_length = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.Length"),
        short_name="Length",
        length_exp=1,
    )
    pdim_mass = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.Mass"),
        short_name="Mass",
        mass_exp=1,
    )
    pdim_time = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.Time"),
        short_name="Time",
        time_exp=1,
    )
    pdim_frequency = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.Frequency"),
        short_name="Frequency",
        time_exp=-1,
    )
    pdim_velocity = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.Velocity"),
        short_name="Velocity",
        length_exp=1,
        time_exp=-1,
    )
    pdim_acceleration = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.Acceleration"),
        short_name="Acceleration",
        length_exp=1,
        time_exp=-2,
    )
    pdim_force = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.Force"),
        short_name="Force",
        length_exp=1,
        mass_exp=1,
        time_exp=-2,
    )
    pdim_pressure = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.Pressure"),
        short_name="Pressure",
        length_exp=-1,
        mass_exp=1,
        time_exp=-2,
    )
    pdim_pressure_divided_by_time = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.PressureDividedByTime"),
        short_name="PressureDividedByTime",
        length_exp=-1,
        mass_exp=1,
        time_exp=-3,
    )
    pdim_torque = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.Torque"),
        short_name="Torque",
        length_exp=2,
        mass_exp=1,
        time_exp=-2,
    )
    pdim_energy = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.Energy"),
        short_name="Energy",
        length_exp=2,
        mass_exp=1,
        time_exp=-2,
    )
    pdim_power = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.Power"),
        short_name="Power",
        length_exp=2,
        mass_exp=1,
        time_exp=-3,
    )
    pdim_electric_current = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.ElectricCurrent"),
        short_name="ElectricCurrent",
        current_exp=1,
    )
    pdim_electric_potential_difference = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.ElectricPotentialDifference"),
        short_name="ElectricPotentialDifference",
        length_exp=2,
        mass_exp=1,
        time_exp=-3,
        current_exp=-1,
    )
    pdim_electric_resistance = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.ElectricResistance"),
        short_name="ElectricResistance",
        length_exp=2,
        mass_exp=1,
        time_exp=-3,
        current_exp=-2,
    )
    pdim_electric_charge = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.ElectricCharge"),
        short_name="ElectricCharge",
        time_exp=1,
        current_exp=1,
    )
    pdim_capacitance = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.Capacitance"),
        short_name="Capacitance",
        length_exp=-2,
        mass_exp=-1,
        time_exp=4,
        current_exp=2,
    )
    pdim_thermodynamic_temperature = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.ThermodynamicTemperature"),
        short_name="ThermodynamicTemperature",
        temperature_exp=1,
    )
    pdim_thermodynamic_temperature_divided_by_time = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.ThermodynamicTemperatureDividedByTime"),
        short_name="ThermodynamicTemperatureDividedByTime",
        time_exp=-1,
        temperature_exp=1,
    )
    pdim_plane_angle = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.PlaneAngle"),
        short_name="PlaneAngle",
    )
    pdim_angular_velocity = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.AngularVelocity"),
        short_name="AngularVelocity",
        time_exp=-1,
    )
    pdim_angular_acceleration = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.AngularAcceleration"),
        short_name="AngularAcceleration",
        time_exp=-2,
    )
    pdim_rotational_speed = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.RotationalSpeed"),
        short_name="RotationalSpeed",
        time_exp=-1,
    )
    pdim_volume = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.Volume"),
        short_name="Volume",
        length_exp=3,
    )
    pdim_volume_flow = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.VolumeFlow"),
        short_name="VolumeFlow",
        length_exp=3,
        time_exp=1,
    )
    pdim_mass_flow = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.MassFlow"),
        short_name="MassFlow",
        mass_exp=1,
        time_exp=-1,
    )
    pdim_mass_density = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.MassDensity"),
        short_name="MassDensity",
        length_exp=-3,
        mass_exp=1,
    )
    pdim_area = PhysicalDimension(
        odx_id=derived_id(dlr, "PDIM.Area"),
        short_name="Area",
        length_exp=2,
    )

    physical_dimensions = NamedItemList(
        [
            pdim_raw,
            pdim_length,
            pdim_mass,
            pdim_time,
            pdim_frequency,
            pdim_velocity,
            pdim_acceleration,
            pdim_force,
            pdim_pressure,
            pdim_pressure_divided_by_time,
            pdim_torque,
            pdim_energy,
            pdim_power,
            pdim_electric_current,
            pdim_electric_potential_difference,
            pdim_electric_resistance,
            pdim_electric_charge,
            pdim_capacitance,
            pdim_thermodynamic_temperature,
            pdim_thermodynamic_temperature_divided_by_time,
            pdim_plane_angle,
            pdim_angular_velocity,
            pdim_angular_acceleration,
            pdim_rotational_speed,
            pdim_volume,
            pdim_volume_flow,
            pdim_mass_flow,
            pdim_mass_density,
            pdim_area,
        ]
    )

    # --- Units ---
    # Helper to create a physical dimension ref
    def pdim_ref(pdim: PhysicalDimension):
        return ref(pdim)

    units = NamedItemList(
        [
            # Dimensionless / Raw
            Unit(
                odx_id=derived_id(dlr, "UNIT.PerCent"),
                short_name="PerCent",
                display_name="%",
                factor_si_to_unit=0.01,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_raw),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.PerMille"),
                short_name="PerMille",
                display_name="\u2030",
                factor_si_to_unit=1000,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_raw),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.Counts"),
                short_name="Counts",
                display_name="counts",
                factor_si_to_unit=1,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_raw),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.Lambda"),
                short_name="Lambda",
                display_name="lambda",
                factor_si_to_unit=1,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_raw),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.PartsPerMillion"),
                short_name="PartsPerMillion",
                display_name="ppm",
                factor_si_to_unit=1000000,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_raw),
            ),
            # Length
            Unit(
                odx_id=derived_id(dlr, "UNIT.Meter"),
                short_name="Meter",
                display_name="m",
                factor_si_to_unit=1,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_length),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.MilliMeter"),
                short_name="MilliMeter",
                display_name="mm",
                factor_si_to_unit=0.001,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_length),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.CentiMeter"),
                short_name="CentiMeter",
                display_name="cm",
                factor_si_to_unit=0.01,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_length),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.KiloMeter"),
                short_name="KiloMeter",
                display_name="km",
                factor_si_to_unit=1000,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_length),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.ThousandKiloMeter"),
                short_name="ThousandKiloMeter",
                display_name="Tkm",
                factor_si_to_unit=0.000001,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_length),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.Mile"),
                short_name="Mile",
                display_name="mi",
                factor_si_to_unit=1609.344,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_length),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.Inch"),
                short_name="Inch",
                display_name="in",
                factor_si_to_unit=0.0254,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_length),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.Foot"),
                short_name="Foot",
                display_name="ft",
                factor_si_to_unit=0.3048,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_length),
            ),
            # Mass
            Unit(
                odx_id=derived_id(dlr, "UNIT.Gram"),
                short_name="Gram",
                display_name="g",
                factor_si_to_unit=0.001,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_mass),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.KiloGram"),
                short_name="KiloGram",
                display_name="kg",
                factor_si_to_unit=1,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_mass),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.MilliGram"),
                short_name="MilliGram",
                display_name="mg",
                factor_si_to_unit=1e-06,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_mass),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.Tonne"),
                short_name="Tonne",
                display_name="t",
                factor_si_to_unit=1000,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_mass),
            ),
            # Time
            Unit(
                odx_id=derived_id(dlr, "UNIT.Second"),
                short_name="Second",
                display_name="s",
                factor_si_to_unit=1,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_time),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.MilliSecond"),
                short_name="MilliSecond",
                display_name="ms",
                factor_si_to_unit=0.001,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_time),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.Microsecond"),
                short_name="Microsecond",
                display_name="\u00b5s",
                factor_si_to_unit=1e-06,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_time),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.Minute"),
                short_name="Minute",
                display_name="min",
                factor_si_to_unit=60,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_time),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.Hour"),
                short_name="Hour",
                display_name="h",
                factor_si_to_unit=3600,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_time),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.Day"),
                short_name="Day",
                display_name="d",
                factor_si_to_unit=86400,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_time),
            ),
            # Temperature
            Unit(
                odx_id=derived_id(dlr, "UNIT.Kelvin"),
                short_name="Kelvin",
                display_name="K",
                factor_si_to_unit=1,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_thermodynamic_temperature),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.DegreeCelsius"),
                short_name="DegreeCelsius",
                display_name="\u00b0C",
                factor_si_to_unit=1,
                offset_si_to_unit=273.15,
                physical_dimension_ref=pdim_ref(pdim_thermodynamic_temperature),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.DegreeFahrenheit"),
                short_name="DegreeFahrenheit",
                display_name="\u00b0F",
                factor_si_to_unit=0.5555555555555,
                offset_si_to_unit=255.37222222222222,
                physical_dimension_ref=pdim_ref(pdim_thermodynamic_temperature),
            ),
            # Frequency
            Unit(
                odx_id=derived_id(dlr, "UNIT.Hertz"),
                short_name="Hertz",
                display_name="Hz",
                factor_si_to_unit=1,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_frequency),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.KiloHertz"),
                short_name="KiloHertz",
                display_name="kHz",
                factor_si_to_unit=1000,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_frequency),
            ),
            # Velocity
            Unit(
                odx_id=derived_id(dlr, "UNIT.MeterPerSecond"),
                short_name="MeterPerSecond",
                display_name="m/s",
                factor_si_to_unit=1,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_velocity),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.KiloMeterPerHour"),
                short_name="KiloMeterPerHour",
                display_name="km/h",
                factor_si_to_unit=0.27777777777777778,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_velocity),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.MilesPerHour"),
                short_name="MilesPerHour",
                display_name="mph",
                factor_si_to_unit=0.44704,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_velocity),
            ),
            # Acceleration
            Unit(
                odx_id=derived_id(dlr, "UNIT.MeterPerSecondSquared"),
                short_name="MeterPerSecondSquared",
                display_name="m/s\u00b2",
                factor_si_to_unit=1,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_acceleration),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.KiloMeterPerHourPerSecond"),
                short_name="KiloMeterPerHourPerSecond",
                display_name="(km/h)/s",
                factor_si_to_unit=3.6,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_acceleration),
            ),
            # Force
            Unit(
                odx_id=derived_id(dlr, "UNIT.Newton"),
                short_name="Newton",
                display_name="N",
                factor_si_to_unit=1,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_force),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.Kilonewton"),
                short_name="Kilonewton",
                display_name="kN",
                factor_si_to_unit=1000,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_force),
            ),
            # Pressure
            Unit(
                odx_id=derived_id(dlr, "UNIT.Pascal"),
                short_name="Pascal",
                display_name="Pa",
                factor_si_to_unit=1,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_pressure),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.KiloPascal"),
                short_name="KiloPascal",
                display_name="kPa",
                factor_si_to_unit=1000,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_pressure),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.HectoPascal"),
                short_name="HectoPascal",
                display_name="hPa",
                factor_si_to_unit=100,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_pressure),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.Bar"),
                short_name="Bar",
                display_name="bar",
                factor_si_to_unit=1e5,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_pressure),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.MilliBar"),
                short_name="MilliBar",
                display_name="mbar",
                factor_si_to_unit=100,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_pressure),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.MegaPascal"),
                short_name="MegaPascal",
                display_name="MPa",
                factor_si_to_unit=1000000,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_pressure),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.PoundForcePerSquareInch"),
                short_name="PoundForcePerSquareInch",
                display_name="psi",
                factor_si_to_unit=6894.7570,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_pressure),
            ),
            # Pressure / Time
            Unit(
                odx_id=derived_id(dlr, "UNIT.BarPerSecond"),
                short_name="BarPerSecond",
                display_name="bar/s",
                factor_si_to_unit=1e5,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_pressure_divided_by_time),
            ),
            # Torque
            Unit(
                odx_id=derived_id(dlr, "UNIT.NewtonMeter"),
                short_name="NewtonMeter",
                display_name="N\u00b7m",
                factor_si_to_unit=1,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_torque),
            ),
            # Energy
            Unit(
                odx_id=derived_id(dlr, "UNIT.Joule"),
                short_name="Joule",
                display_name="J",
                factor_si_to_unit=1,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_energy),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.KiloJoule"),
                short_name="KiloJoule",
                display_name="kJ",
                factor_si_to_unit=1000,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_energy),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.KilowattHour"),
                short_name="KilowattHour",
                display_name="kWh",
                factor_si_to_unit=3.6e6,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_energy),
            ),
            # Power
            Unit(
                odx_id=derived_id(dlr, "UNIT.Watt"),
                short_name="Watt",
                display_name="W",
                factor_si_to_unit=1,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_power),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.KiloWatt"),
                short_name="KiloWatt",
                display_name="kW",
                factor_si_to_unit=1000,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_power),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.GigaWatt"),
                short_name="GigaWatt",
                display_name="GW",
                factor_si_to_unit=1e9,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_power),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.NewtonMeterPerSecond"),
                short_name="NewtonMeterPerSecond",
                display_name="(N\u00b7m)/s",
                factor_si_to_unit=1,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_power),
            ),
            # Electric Current
            Unit(
                odx_id=derived_id(dlr, "UNIT.Ampere"),
                short_name="Ampere",
                display_name="A",
                factor_si_to_unit=1,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_electric_current),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.MilliAmpere"),
                short_name="MilliAmpere",
                display_name="mA",
                factor_si_to_unit=0.001,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_electric_current),
            ),
            # Electric Potential Difference
            Unit(
                odx_id=derived_id(dlr, "UNIT.Volt"),
                short_name="Volt",
                display_name="V",
                factor_si_to_unit=1,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_electric_potential_difference),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.MilliVolt"),
                short_name="MilliVolt",
                display_name="mV",
                factor_si_to_unit=0.001,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_electric_potential_difference),
            ),
            # Electric Resistance
            Unit(
                odx_id=derived_id(dlr, "UNIT.Ohm"),
                short_name="Ohm",
                display_name="\u03a9",
                factor_si_to_unit=1,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_electric_resistance),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.KiloOhm"),
                short_name="KiloOhm",
                display_name="k\u03a9",
                factor_si_to_unit=1000,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_electric_resistance),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.MilliOhm"),
                short_name="MilliOhm",
                display_name="m\u03a9",
                factor_si_to_unit=0.001,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_electric_resistance),
            ),
            # Electric Charge
            Unit(
                odx_id=derived_id(dlr, "UNIT.AmpereHour"),
                short_name="AmpereHour",
                display_name="Ah",
                factor_si_to_unit=3600,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_electric_charge),
            ),
            # Capacitance
            Unit(
                odx_id=derived_id(dlr, "UNIT.Farad"),
                short_name="Farad",
                display_name="F",
                factor_si_to_unit=1,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_capacitance),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.Microfarad"),
                short_name="Microfarad",
                display_name="\u00b5F",
                factor_si_to_unit=0.001,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_capacitance),
            ),
            # Rotational Speed
            Unit(
                odx_id=derived_id(dlr, "UNIT.RevolutionsPerMinute"),
                short_name="RevolutionsPerMinute",
                display_name="rpm",
                factor_si_to_unit=0.016666666666666667,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_rotational_speed),
            ),
            # Angular Velocity
            Unit(
                odx_id=derived_id(dlr, "UNIT.DegreePerSecond"),
                short_name="DegreePerSecond",
                display_name="\u00b0/s",
                factor_si_to_unit=0.017453292519943296,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_angular_velocity),
            ),
            # Plane Angle
            Unit(
                odx_id=derived_id(dlr, "UNIT.Degree"),
                short_name="Degree",
                display_name="\u00b0",
                factor_si_to_unit=0.01745329252,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_plane_angle),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.Radian"),
                short_name="Radian",
                display_name="rad",
                factor_si_to_unit=1,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_plane_angle),
            ),
            # Volume
            Unit(
                odx_id=derived_id(dlr, "UNIT.Liter"),
                short_name="Liter",
                display_name="l",
                factor_si_to_unit=0.001,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_volume),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.MilliLiter"),
                short_name="MilliLiter",
                display_name="ml",
                factor_si_to_unit=1e-6,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_volume),
            ),
            # Volume Flow
            Unit(
                odx_id=derived_id(dlr, "UNIT.LiterPerHour"),
                short_name="LiterPerHour",
                display_name="l/h",
                factor_si_to_unit=2.77777777777778e-7,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_volume_flow),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.LiterPerMinute"),
                short_name="LiterPerMinute",
                display_name="l/min",
                factor_si_to_unit=1.666666666667e-5,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_volume_flow),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.LiterPer100Km"),
                short_name="LiterPer100Km",
                display_name="l/100km",
                factor_si_to_unit=1e-8,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_volume_flow),
            ),
            # Mass Flow
            Unit(
                odx_id=derived_id(dlr, "UNIT.GramPerSecond"),
                short_name="GramPerSecond",
                display_name="g/s",
                factor_si_to_unit=0.001,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_mass_flow),
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.KiloGramPerHour"),
                short_name="KiloGramPerHour",
                display_name="kg/h",
                factor_si_to_unit=0.00027777777777777778,
                offset_si_to_unit=0,
                physical_dimension_ref=pdim_ref(pdim_mass_flow),
            ),
            # Storage / Data (no physical dimension / SI conversion)
            Unit(
                odx_id=derived_id(dlr, "UNIT.Bit"),
                short_name="Bit",
                display_name="bit",
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.Byte"),
                short_name="Byte",
                display_name="B",
            ),
            Unit(
                odx_id=derived_id(dlr, "UNIT.KiloByte"),
                short_name="KiloByte",
                display_name="kB",
            ),
        ]
    )

    dlr.diag_data_dictionary_spec.unit_spec = UnitSpec(
        physical_dimensions=physical_dimensions,
        units=units,
    )
