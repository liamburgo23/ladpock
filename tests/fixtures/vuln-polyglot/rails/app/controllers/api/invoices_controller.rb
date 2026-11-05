class Api::InvoicesController < ApplicationController
  before_action :set_invoice

  def show
    render json: @invoice
  end

  def destroy
    @invoice.destroy
    head :no_content
  end

  def refund
    @invoice.update(refunded: true)
    head :ok
  end

  private

  def set_invoice
    @invoice = Invoice.find(params[:id])
  end
end
