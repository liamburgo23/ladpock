class Api::InvoicesController < ApplicationController
  before_action :set_invoice

  def show
    render json: @invoice
  end

  def destroy
    @invoice.destroy
    head :no_content
  end

  private

  def set_invoice
    @invoice = current_user.invoices.find(params[:id])
  end
end
