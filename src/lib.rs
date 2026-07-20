//! Tulle: the shared radio interface layer for LoRa mesh stacks.
//!
//! Tulle is the seam between protocol stacks and radio hardware: serial modem
//! control (RNode/KISS style framing), and medium access (listen-before-talk,
//! duty-cycle accounting) shared by every protocol on the same radio. It sits
//! beneath [retinue](https://github.com/mark-ik/retinue) and its mesh interop
//! siblings, tucket and sennet.
//!
//! This release reserves the name; the crate is under active design.
//! A tulle is a fine net fabric: the material every protocol is woven across.
