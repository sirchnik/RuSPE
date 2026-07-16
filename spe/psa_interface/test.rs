use bytemuck::checked;
fn foo() {
    let _ = checked::from_bytes::<()>;
}
