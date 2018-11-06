/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use bindgen;

use std::fs::File;
use std::io::Write;

use headers;

impl super::BuildConfig {
    pub fn bindgen(&self) {
        let header = self.out_dir.join("bindgen-input.h");
        File::create(&header)
            .and_then(|mut f| {
                Ok(for h in headers::enabled_ordered() {
                    try!(writeln!(f, "#include <mbedtls/{}>", h));
                })
            }).expect("bindgen-input.h I/O error");

        let include = self.mbedtls_src.join("include");

        let bindings = bindgen::builder()
            .clang_arg("-Dmbedtls_t_udbl=mbedtls_t_udbl;") // bindgen can't handle unused uint128
            .clang_arg(format!(
                "-DMBEDTLS_CONFIG_FILE=<{}>",
                self.config_h.to_str().expect("config.h UTF-8 error")
            )).clang_arg(format!(
                "-I{}",
                include.to_str().expect("include/ UTF-8 error")
            )).header(
                header
                    .to_str()
                    .expect("failed to convert header path to string"),
            ).use_core()
            .derive_debug(false) // buggy :(
            .disable_name_namespacing()
            .prepend_enum_name(false)
            .ctypes_prefix("raw_types")
            .blacklist_type("MBEDTLS_SSL_SESSION_TICKETS_ENABLED")
            .generate()
            .expect("bindgen error");

        let bindings_rs = self.out_dir.join("bindings.rs");
        File::create(&bindings_rs)
            .and_then(|mut f| {
                try!(bindings.write(Box::new(&mut f)));
                f.write_all(b"use ::types::*;\n") // for FILE, time_t, etc.
            }).expect("bindings.rs I/O error");

        let mod_bindings = self.out_dir.join("mod-bindings.rs");
        File::create(&mod_bindings)
            .and_then(|mut f| f.write_all(b"mod bindings;\n"))
            .expect("mod-bindings.rs I/O error");
    }
}
