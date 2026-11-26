/** Deliberately bounded UI feedback. Never render a raw server diagnostic. */
export function actionFeedback(message:string,error:boolean):string{
  if(!error){
    if(!message||['Checking session…','Managed device configuration loaded.','Local identity inventory loaded.','Policy version selection changed. Load the version to inspect its metadata.'].includes(message))return '';
    if(message==='Authenticated session.'||message==='Sign in to manage this appliance.')return '';
    if(message==='Signed out.')return 'Signed out.';
    if(message==='Password changed. Sign in again with your new password.')return message;
    return 'Action completed.';
  }
  const safeMessages:Record<string,string>={
    'authentication required':'Please sign in again.',
    'authentication failed':'Sign-in failed. Check your credentials.',
    'username unavailable':'Username is in use or reserved by a removed account.',
    'identity protected':'This account is protected or unavailable.',
    'permission denied':'You do not have permission for this action.',
    'New password confirmation does not match.':'New password confirmation does not match.',
    'Enter a policy version ID.':'Select a policy first.'
  };
  return safeMessages[message]??'Action failed. Check your input and try again.';
}
