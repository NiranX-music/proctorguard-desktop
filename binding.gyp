{
  "targets": [
    {
      "target_name": "desktop_auditor",
      "sources": [
        "src-native/addon.cc",
        "src-native/process_checker.cc",
        "src-native/module_auditor.cc",
        "src-native/display_auditor.cc"
      ],
      "include_dirs": [
        "src-native"
      ],
      "conditions": [
        ["OS=='win'", {
          "libraries": [
            "-lpsapi.lib",
            "-luser32.lib",
            "-lkernel32.lib",
            "-lgdi32.lib"
          ],
          "msvs_settings": {
            "VCCLCompilerTool": {
              "ExceptionHandling": 1,
              "AdditionalOptions": [ "/std:c++17", "/utf-8" ]
            }
          },
          "defines": [
            "UNICODE",
            "_UNICODE",
            "WIN32_LEAN_AND_MEAN"
          ]
        }]
      ]
    }
  ]
}
