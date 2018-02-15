#[macro_use]
extern crate lazy_static;

use std::fs::copy;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard};

lazy_static! {
    static ref C_TEST_MUTEX: Mutex<()> = Mutex::new(());
}

fn assert_output_success(output: Output) {
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("Stdout:\n{}\nStderr:\n{}\n", stdout, stderr);
        panic!("Running C tests failed with non-zero return code");
    }
}

fn build_tests() -> (MutexGuard<'static, ()>, PathBuf) {
    let guard = match C_TEST_MUTEX.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let out_dir = env!("OUT_DIR");
    let build_dir = Path::new(out_dir).join("build");

    println!("Running meson...");
    Command::new("meson")
        .arg(build_dir.to_str().unwrap())
        .env("CC", "clang")
        .output()
        .expect("Could not run meson to build C tests");

    println!("Running ninja...");
    let output = Command::new("ninja")
        .current_dir(&build_dir)
        .output()
        .expect("Could not run ninja to build C tests");
    assert_output_success(output);

    println!("Copying test certificate...");
    copy("../saltyrtc.der", build_dir.join("saltyrtc.der"))
        .expect("Could not copy test certificate (saltyrtc.der)");

    (guard, build_dir)
}

#[test]
fn c_tests_run() {
    let (_guard, build_dir) = build_tests();

    let output = Command::new("./tests")
        .current_dir(&build_dir)
        .output()
        .expect("Could not run C tests");
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("Stdout:\n{}\nStderr:\n{}\n", stdout, stderr);
        panic!("Running C tests failed with non-zero return code");
    }
}

// #[test] Disabled for now due to false errors, see
// https://bugs.kde.org/show_bug.cgi?id=381289 and
// https://bugzilla.redhat.com/show_bug.cgi?id=1462258
fn c_tests_no_memory_leaks() {
    let (_guard, build_dir) = build_tests();

    let output = Command::new("valgrind")
        .arg("--error-exitcode=23")
        .arg("--leak-check=full")
        .arg("--track-fds=yes")
        .arg("./tests")
        .current_dir(&build_dir)
        .output()
        .expect("Could not run valgrind");
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("Stdout:\n{}\nStderr:\n{}\n", stdout, stderr);
        panic!("Running valgrind failed with non-zero return code");
    }
}
