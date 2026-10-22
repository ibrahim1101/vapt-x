"""Operator-only streaming re-encryption. Dry-run default; never prints stored values."""
import argparse
import asyncio
import json
import os
import sys
from cryptography.fernet import Fernet,MultiFernet,InvalidToken
from motor.motor_asyncio import AsyncIOMotorClient

PURPOSES={
 'mfa':('MFA_ENCRYPTION_KEYS','users',('mfa_secret','mfa_pending.secret')),
 'webhook':('WEBHOOK_ENCRYPTION_KEYS','webhooks',('encrypted_configuration',)),
 'oidc':('OIDC_ENCRYPTION_KEYS','oidc_flows',('verifier',)),
}

def keyrings(purposes,env):
    rings={}
    for purpose in purposes:
        variable=PURPOSES[purpose][0]
        values=[value.strip() for value in env.get(variable,'').split(',') if value.strip()]
        if not values:raise ValueError('Every selected purpose requires its configured encryption key ring')
        try:keys=[Fernet(value.encode()) for value in values]
        except (ValueError,TypeError):raise ValueError('An encryption key ring is invalid') from None
        rings[purpose]=(keys[0],MultiFernet(keys))
    return rings

def nested(document,path):
    value=document
    for name in path.split('.'):
        if not isinstance(value,dict) or name not in value:return None
        value=value[name]
    return value

async def rewrap(database,purposes,rings,apply=False):
    """Compare-and-swap only ciphertext; retain secret values, epochs and timestamps."""
    summaries=[]
    for purpose in purposes:
        _,collection,fields=PURPOSES[purpose]
        primary,ring=rings[purpose]
        for field in fields:
            counts={'purpose':purpose,'field':field,'scanned':0,'current':0,'would_update':0,'updated':0,'conflicts':0,'invalid':0}
            cursor=database[collection].find({field:{'$exists':True}},{'_id':1,field:1}).sort('_id',1).batch_size(100)
            async for document in cursor:
                counts['scanned']+=1
                old=nested(document,field)
                if not isinstance(old,str) or not 1<=len(old)<=16384:
                    counts['invalid']+=1;continue
                try:
                    token=old.encode('ascii')
                    try:primary.decrypt(token);counts['current']+=1;continue
                    except InvalidToken:pass
                    # MultiFernet.rotate preserves the original Fernet timestamp.
                    replacement=ring.rotate(token).decode('ascii')
                except (ValueError,TypeError,UnicodeError,InvalidToken):
                    counts['invalid']+=1;continue
                counts['would_update']+=1
                if apply:
                    result=await database[collection].update_one({'_id':document['_id'],field:old},{'$set':{field:replacement}})
                    counts['updated' if result.modified_count==1 else 'conflicts']+=1
            summaries.append(counts)
    return {'mode':'apply' if apply else 'dry-run','fields':summaries,
        'remaining':sum(row['would_update']-row['updated'] for row in summaries),
        'ok':not any(row['invalid'] or row['conflicts'] for row in summaries)}

def arguments(argv=None):
    parser=argparse.ArgumentParser(description='Rewrap stored Fernet secrets to the first key, without revealing values. Defaults to dry-run.')
    parser.add_argument('--purpose',action='append',choices=sorted(PURPOSES),required=True,help='Repeat to select multiple independent key rings')
    parser.add_argument('--apply',action='store_true',help='Write conditional ciphertext updates; omit to inspect counts only')
    return parser.parse_args(argv)

async def execute(args,env):
    purposes=list(dict.fromkeys(args.purpose));rings=keyrings(purposes,env)
    if not env.get('MONGO_URL') or not env.get('DB_NAME'):raise ValueError('MONGO_URL and DB_NAME are required')
    client=AsyncIOMotorClient(env['MONGO_URL'],serverSelectionTimeoutMS=5000,connectTimeoutMS=5000,socketTimeoutMS=10000)
    try:
        database=client[env['DB_NAME']]
        await database.command('ping')
        return await rewrap(database,purposes,rings,apply=args.apply)
    finally:client.close()

def main(argv=None):
    args=arguments(argv)
    try:
        result=asyncio.run(execute(args,os.environ))
    except KeyboardInterrupt:
        print('Rewrapping interrupted; retain all keys and rerun the dry-run.',file=sys.stderr);return 130
    except Exception:
        print('Rewrapping failed. Check selected key rings and database configuration; retain all existing keys.',file=sys.stderr);return 2
    print(json.dumps(result,sort_keys=True))
    return 0 if result['ok'] else 2

if __name__=='__main__':sys.exit(main())
