function confirmSavedDeviceKey(label, cancelLabel, confirmLabel) {
  return new Promise((resolve) => {
    const dialog = document.createElement('dialog');
    dialog.className = 'device-key-confirmation';
    dialog.setAttribute('aria-label', label);
    const form = document.createElement('form');
    const field = document.createElement('label');
    const password = document.createElement('input');
    password.type = 'password';
    password.autocomplete = 'current-password';
    password.required = true;
    password.maxLength = 1024;
    field.append(label, password);
    const actions = document.createElement('div');
    actions.className = 'actions';
    const cancel = document.createElement('button');
    cancel.type = 'button';
    cancel.className = 'secondary';
    cancel.textContent = cancelLabel;
    cancel.addEventListener('click', () => dialog.close());
    const confirm = document.createElement('button');
    confirm.type = 'submit';
    confirm.textContent = confirmLabel;
    actions.append(cancel, confirm);
    form.append(field, actions);
    dialog.append(form);
    document.body.append(dialog);
    let value = null;
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      value = password.value;
      password.value = '';
      dialog.close();
    });
    dialog.addEventListener('close', () => {
      password.value = '';
      dialog.remove();
      resolve(value);
      value = null;
    }, {once: true});
    dialog.showModal();
    password.focus();
  });
}
