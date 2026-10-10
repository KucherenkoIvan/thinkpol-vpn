package wg

func IpcGetForTest(d *Device) string {
	s, _ := d.dev.IpcGet()
	return s
}
