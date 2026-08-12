rule minimal_yara {
    strings:
        $a = "test"
    condition:
        $a
}
