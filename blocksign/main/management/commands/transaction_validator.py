import logging
import time

from datetime import timedelta

from django.utils import timezone

from django.core.management.base import BaseCommand, CommandError

from main.bc_connector import get_bcobj

from main.models import Document, DocumentStatus

logger = logging.getLogger('blocksign')


class Command(BaseCommand):
    help = 'Recorre las txs no validadas y comprueba si se han validado'

    def handle(self, *args, **options):
        logger.debug("Comienzo del Command 'transaction_validator'")
        while True:
            logger.info("Pending transactions ...")
            bcobj = get_bcobj()
            try:
                status_pending = DocumentStatus.objects.get(name="Pendiente")
            except:
                logger.error("No se ha encontrado el estado 'Pendiente'")
                return None
            pending_txs = Document.objects.filter(status=status_pending)
            for tx in pending_txs:
                if bcobj.is_validated(tx.tx_id):
                    try:
                        status = DocumentStatus.objects.get(name="Confirmado")
                    except DocumentStatus.DoesNotExist:
                        logger.error("No se ha encontrado el estado 'Confirmado'")
                        return None
                    tx.status = status
                    tx.save()
                    logger.info(f'Transacción {tx.tx_id} validada')
                elif (tx.timestamp + timedelta(seconds=60)) < timezone.now():
                    try:
                        status = DocumentStatus.objects.get(name="Rechazado")
                    except Exception as e:
                        logger.error("No se ha encontrado el estado 'Rechazado'")
                        return None
                    tx.status = status
                    tx.save()
                    logger.warning(f'Transacción {tx.tx_id} rechazada')
            time.sleep(5)
