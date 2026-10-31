{ pkgs, tameshi }:
let
  inherit (pkgs) lib;
  receiptFile = "tameshi-receipt.v1.json";
  fragmentFile = "tameshi-fragment.v1.json";

  argvOf = command:
    if builtins.isList command then command
    else [ "${pkgs.bash}/bin/bash" "-c" command ];

  hashArgs = flag: spec:
    if spec ? hash then [ "--${flag}-hash" spec.hash ]
    else if spec ? path then [ "--${flag}-path" "${spec.path}" ]
    else throw "tameshi wrapTest: ${flag} needs `hash` (b3:<hex>) or `path`";

  wrapTest =
    { name
    , command
    , controls
    , target
    , test
    , src ? null
    , nativeBuildInputs ? [ ]
    , env ? { }
    , threshold ? true
    }:
    let
      system = pkgs.stdenv.hostPlatform.system;
      run = pkgs.stdenv.mkDerivation (env // {
        name = "${name}-run";
        dontUnpack = src == null;
        nativeBuildInputs = [ tameshi ] ++ nativeBuildInputs;
        dontConfigure = true;
        dontInstall = true;
        dontFixup = true;
        buildPhase = "tameshi receipt run --out \"$out\" --fresh-home -- ${lib.escapeShellArgs (argvOf command)}";
      } // lib.optionalAttrs (src != null) { inherit src; });
      writeArgs =
        [ "--run" "${run}" "--derivation" (builtins.unsafeDiscardStringContext run.drvPath) "--system" system ]
        ++ lib.concatMap (control: [ "--control" control ]) controls
        ++ [ "--target-kind" target.kind ] ++ hashArgs "target" target
        ++ [ "--runner" test.runner ] ++ hashArgs "test" test;
    in
    pkgs.runCommand name
      {
        nativeBuildInputs = [ tameshi ];
        passthru = { inherit run; };
        TAMESHI_FRAGMENT_THRESHOLD__ENABLED = lib.boolToString threshold;
      } ''
      tameshi receipt write ${lib.escapeShellArgs writeArgs} --out "$out"
      tameshi receipt verify "$out/${receiptFile}" --fragment "$out/${fragmentFile}"
    '';

  fixture = ../tests/fixtures/receipt-crate;
  fixtureTest = name: extra: threshold: wrapTest {
    inherit name threshold;
    src = fixture;
    nativeBuildInputs = [ pkgs.cargo pkgs.rustc ];
    controls = [ "NIST_SP_800_53R5_SA_11" "NIST_SP_800_53R5_SI_7" ];
    target = { kind = "nix-output"; path = fixture + "/src"; };
    test = { runner = "cargo"; path = fixture + "/tests"; };
    command = [ "cargo" "test" "--offline" ] ++ extra;
  };
  pass = fixtureTest "receipt-fixture-pass" [ ] true;
  fail = fixtureTest "receipt-fixture-fail" [ "--features" "fail" ] true;
  singleKey = fixtureTest "receipt-fixture-single-key" [ ] false;

  proofCheck = { name, fold, evidence, control, status }:
    pkgs.runCommand name { nativeBuildInputs = [ tameshi ]; } ''
      tameshi ${fold} --out "$out/ledger.json"
      tameshi ledger prove "$out/ledger.json" ${evidence} --control ${control} --out "$out/proof.json"
      tameshi ledger verify "$out/proof.json" --ledger "$out/ledger.json" ${evidence} --control ${control} --expect-status ${status}
    '';
  passProof = proofCheck {
    name = "receipt-pass-proof";
    fold = "ledger fold \"$out/ledger.json\" ${pass}/${receiptFile} ${fail}/${receiptFile}";
    evidence = "--receipt ${pass}/${receiptFile}";
    control = "NIST_SP_800_53R5_SA_11";
    status = "PASS";
  };
  failProof = proofCheck {
    name = "receipt-fail-proof";
    fold = "ledger fold \"$out/ledger.json\" ${fail}/${receiptFile} ${pass}/${receiptFile}";
    evidence = "--receipt ${fail}/${receiptFile}";
    control = "NIST_SP_800_53R5_SI_7";
    status = "FAIL";
  };
  incidentProof = proofCheck {
    name = "receipt-incident-proof";
    fold = "incident ingest ${passProof}/ledger.json ${../tests/fixtures/sample.bluecrash}";
    evidence = "--bluecrash ${../tests/fixtures/sample.bluecrash}";
    control = "NIST_SP_800_53R5_IR_5";
    status = "INCIDENT";
  };
in
{
  inherit wrapTest;
  checks = {
    receipt-pass = pass;
    receipt-fail = fail;
    receipt-single-key = singleKey;
    receipt-pass-proof = passProof;
    receipt-fail-proof = failProof;
    receipt-incident-proof = incidentProof;
  };
}
