package ru.hw.blowfish.enums;

import lombok.Getter;

import java.util.Arrays;

public enum EncipherMode {
    ECB(0),
    CBC(1),
    PCBC(2),
    OFB(3);

    @Getter
    private int code;

    EncipherMode(int code) {
        this.code = code;
    }

    public static EncipherMode getByCode(int code) {
        return Arrays
                .stream(EncipherMode.values())
                .filter(val -> val.code == code)
                .findFirst()
                .orElseThrow(() -> new RuntimeException("not supported mode"));
    }
}
