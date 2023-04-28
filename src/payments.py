"""
import grpc
import os
import codecs
import logging

RECORD_ID = "34349339"  # Sender pubkey record
# RECORD_ID = "34349334"  # Chat record


# Pulled from recurring_donations
def send_to_node(node, sats):
    sats = str(int(sats))
    logging.info("Sending {0} sats to {1}".format(sats, node))
    my_pubkey = "LOLOLOLOLOL"
    p = subprocess.run(
        ['lncli', 'sendpayment', '--dest='+node, '--amt='+sats, "--data "+RECORD_ID+"="+my_pubkey, "--keysend"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode == 0:
        logging.info("Successfully sent {0} sats".format(sats))

        # TODO: notify server that the payment is complete.
        # TODO: Send payment hash (from p.stdout), and pubkey

        return True
    else:
        logging.info(p.stdout)
        logging.error(p.stderr)


def lndPayInvoice(lnInvoiceString):
    try:
        # call LND GRPC API
        macaroon = codecs.encode(open(LND_ADMIN_MACAROON_PATH, 'rb').read(), 'hex')
        os.environ['GRPC_SSL_CIPHER_SUITES'] = 'HIGH+ECDSA'
        cert = open(LND_TLS_PATH, 'rb').read()
        ssl_creds = grpc.ssl_channel_credentials(cert)
        channel = grpc.secure_channel("{0}:10009".format(LND_IP), ssl_creds)
        stub = rpcstub.LightningStub(channel)
        request = lnrpc.SendRequest(
            payment_request=lnInvoiceString,
        )
        response = stub.SendPaymentSync(request, metadata=[('macaroon', macaroon)])

        # validate results
        if len(response.payment_error) > 0:
            raise BlitzError(response.payment_error, {'invoice': lnInvoiceString})

    except Exception as e:
        raise BlitzError("payment failed", {'invoice': lnInvoiceString}, e)

    return response

"""