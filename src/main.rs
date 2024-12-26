#![no_main]
#![no_std]

extern crate alloc;

use core::panic::PanicInfo;

use framebuffer::{color::Color, raw::write::RawWriter};
use graphics::{
    initialize_framebuffer, logger::LOGGER, parse_psf_font, BG_COLOR, CAPTION, FG_COLOR_CAPTION,
    FG_COLOR_ERROR, FG_COLOR_INFO, FG_COLOR_LOG, FG_COLOR_OK,
};
use log::{error, info};
use memory::KERNEL_STACK_SIZE;
use uefi::prelude::*;

mod error;
mod file;
mod graphics;
mod memory;

const PSF_FILE_NAME: &str = "font.psf";
const KERNEL_FILE_NAME: &str = "kernel.elf";

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    info!("Bootloader: Hello world!");
    info!("Bootloader: Intializing GOP framebuffer...");
    match initialize_framebuffer() {
        Ok(framebuffer) => {
            framebuffer.fill(Color::new(0, 0, 0));
            let font = parse_psf_font(PSF_FILE_NAME).unwrap();

            let writer = RawWriter::new(font, framebuffer, FG_COLOR_LOG, BG_COLOR);

            LOGGER.initialize(writer);

            logln!(FG_COLOR_CAPTION, "{}", CAPTION);

            log!(FG_COLOR_LOG, " [LOG  ]: Initializing framebuffer ");
            logln!(FG_COLOR_OK, "OK");

            // get kernel file from disk
            let kernel_data = validate!(
                file::get_file_data(KERNEL_FILE_NAME),
                "Retrieving kernel file image"
            );

            loginfo!("Kernel size: {} bytes", kernel_data.len());

            let kernel_elf = validate!(
                file::elf::Elf::try_new(kernel_data),
                "Loading kernel image into memory"
            );

            loginfo!(
                "Kernel entry: {:#x}, file base: {:#x}, pages: {:#x}",
                kernel_elf.entry(),
                kernel_elf.base(),
                kernel_elf.num_pages()
            );

            let kernel_stack = validate!(
                memory::allocate_kernel_stack(KERNEL_STACK_SIZE),
                "Allocating memory for kernel stack"
            );
            loginfo!(
                "Kernel stack top: {:#x}, bottom: {:#x}, pages: {:#x}",
                kernel_stack.top(),
                kernel_stack.bottom(),
                kernel_stack.num_pages()
            );

            let (bootinfo_ptr, bootinfo_pages) = validate!(
                memory::allocate_bootinfo(),
                "Allocating memory for kernel bootinfo"
            );
            loginfo!(
                "Kernel boot info start: {:#x}, pages: {:#x}",
                bootinfo_ptr.as_ptr() as u64,
                bootinfo_pages
            );
        }
        // this won't always be shown in the console, because stdout may not be available in some cases
        Err(err) => error!("Bootloader: Failed to initialize framebuffer: {}", err),
    }

    boot::stall(10_000_000);
    Status::SUCCESS
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    error!("Panic occurred: \n{:#?}", info);
    log!(FG_COLOR_ERROR, " [ERROR]: ");
    logln!(FG_COLOR_LOG, "Panic orccurred: \n{:#?}", info);
    loop {}
}
