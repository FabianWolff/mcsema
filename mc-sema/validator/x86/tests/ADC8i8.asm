BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; ADC8i8
    mov al, 0xbb
    ;TEST_BEGIN_RECORDING
    adc al, 0x5
    ;TEST_END_RECORDING
