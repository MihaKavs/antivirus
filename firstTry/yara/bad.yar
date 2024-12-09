rule bad_words {
    strings:
        $badwords = "ben"
    condition:
        $badwords
}