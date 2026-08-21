//! Print this host's captured processor capabilities, one per line. The
//! sdk-portability gate diffs this output against the other four SDKs to
//! prove the cross-SDK capture rule yields one identical list per host.

fn main() {
    for capability in reproit_sdk_rust::capture_processor_capabilities() {
        println!("{capability}");
    }
}
