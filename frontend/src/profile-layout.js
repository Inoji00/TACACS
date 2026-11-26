export function profileLayout({jsx, jsxs, t, name, mfaRequired, passwordForm, languageControl}) {
  const card = (title, children) => jsxs('section', {className:'card profile-card', children:[
    jsx('h2', {children:t(title)}), jsx('div', {className:'profile-card-body', children}),
  ]});
  return jsxs('section', {'data-page':'password', className:'profile-grid', children:[
    jsxs('div', {className:'profile-column', children:[
      card('Password', passwordForm),
      card('Two-factor authentication', jsx('p', {children:t(mfaRequired ? 'Authenticator code required at Web sign-in.' : 'Web sign-in uses a password only.') })),
    ]}),
    jsxs('div', {className:'profile-column', children:[
      card('Account', jsxs('div', {children:[jsxs('div', {className:'profile-identity', children:[
        jsx('span', {className:'account-avatar', 'aria-hidden':true, children:name.charAt(0).toUpperCase()}),
        jsx('strong', {children:name}),
      ]}), jsxs('dl',{className:'profile-facts',children:[
        jsx('dt',{children:t('Email')}), jsx('dd',{children:'—'}),
        jsx('dt',{children:t('Account type')}), jsx('dd',{children:t('Local account')}),
      ]})]})),
      card('Language', languageControl),
    ]}),
  ]});
}
