#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x88d580b, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0xdc3c46c1, __VMLINUX_SYMBOL_STR(__asan_register_globals) },
	{ 0xe894f8f4, __VMLINUX_SYMBOL_STR(__asan_unregister_globals) },
	{ 0xb535d30c, __VMLINUX_SYMBOL_STR(klp_unregister_patch) },
	{ 0x205c6476, __VMLINUX_SYMBOL_STR(klp_enable_patch) },
	{ 0x8a8a9d7c, __VMLINUX_SYMBOL_STR(klp_register_patch) },
	{ 0x4398123c, __VMLINUX_SYMBOL_STR(__asan_report_store8_noabort) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x2c2fa74f, __VMLINUX_SYMBOL_STR(seq_printf) },
	{ 0x5a7a45f8, __VMLINUX_SYMBOL_STR(__sanitizer_cov_trace_pc) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "D3BB9F87B61C603A86F055A");
