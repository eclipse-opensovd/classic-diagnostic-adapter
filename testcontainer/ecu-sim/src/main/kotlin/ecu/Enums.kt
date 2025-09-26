package ecu

import kotlinx.serialization.Serializable

@Serializable
enum class Variant {
    BOOT,
    APPLICATION
}

@Serializable
enum class SessionState(val value: Byte) {
    DEFAULT(0x01),
    PROGRAMMING(0x02),
    EXTENDED(0x03),
    SAFETY(0x04),
    CUSTOM(0x23),
}

@Serializable
enum class SecurityAccess(val level: Byte) {
    LOCKED(0),
    LEVEL_03(3),
    LEVEL_05(5),
    LEVEL_07(7);

    companion object {
        fun parse(level: Byte) =
            entries.firstOrNull { it.level == level }
    }
}

@Serializable
enum class Authentication {
    UNAUTHENTICATED,
    AFTER_MARKET,
    AFTER_SALES,
    DEVELOPMENT,
}

@Serializable
enum class DataBlockType {
    BOOT,
    CODE,
    DATA,
}
